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
  - Follow-up gap closed: `investigate_cve --binary` (this item's own CVE-to-exploit agent)
    builds its exploit plan via `workflows/cveplan.py`'s `plan_for_binary`, which only ever
    called `chainanalyzer.analyze_chains` -- a real exploitation engine, but modeling far fewer
    chains than the full `autopwn()` engine above (29 named techniques vs. chainanalyzer's own
    set). Confirmed live with a genuine counter-example: `chainanalyzer.analyze_chains` against
    `samples/bin/leakchain` (the infoleak-chaining fixture from "Automatic infoleak chaining")
    returns ZERO verified chains, while `autopwn()` has verified `leak-chain` on that exact
    binary since that item shipped. Added `_augment_with_autopwn` to `cveplan.py`: when
    chainanalyzer's own pass doesn't verify anything, `plan_for_binary` now also tries the full
    `autopwn()` engine and, on a hit, fills in `ExploitPlan.verified/proof/concrete["chain"]`
    from autopwn's real sandbox-verified attempt (never overwrites an existing chainanalyzer
    verification). Verified end-to-end through `investigate_cve` itself (not just the helper in
    isolation): investigating a fake CVE ID against `samples/bin/leakchain` with no LLM backend
    and no network now reports "EXPLOIT VERIFICADO en sandbox" with the real leaked libc base
    and `system()` address, where it previously would have fallen through to an unverified
    template. Tests added to `tests/test_tools_and_config.py`: the real leak-chain recovery
    above, a check that an existing verification is never overwritten, and a clean degrade for
    a binary that verifies nothing.
  - Second follow-up quality fix, found investigating a REAL CVE (CVE-2021-3156, "Baron
    Samedit") end to end -- never by executing the actual vulnerable sudo binary (that crosses
    a line this project won't cross: weaponizing a real setuid-root LPE against a live host is
    out of scope, full stop; the finding below came from reading `develop_exploit`'s own output
    for the CVE's classified vulnerability class). `cveplan.py`'s `develop_exploit` generates a
    GENERIC pwntools template per vulnerability class, and for `heap-overflow`/`uaf`/
    `double-free` that template assumes an interactive CTF-style menu (`alloc`/`free`/`show`
    over stdin, `sendlineafter(b'>', ...)` wrappers) -- a reasonable default for this project's
    own `samples/` corpus, but presented with zero caveat even when investigating a REAL CVE on
    a real-world program. Baron Samedit is an off-by-one in `sudo`'s own argv/getenv parsing,
    triggered via `sudoedit -s` and a crafted command-line argument -- nothing remotely like a
    menu, so the generated "exploit" would be actively misleading if followed literally.
    Threaded `has_public_exploit`/`poc_ref_url` (already known to `investigate_cve` via
    `cvelookup.fetch_cve`) through `plan()` / `plan_from_analysis` / `plan_for_binary` /
    `develop_exploit`, across the `binoracle cveplan --json` subprocess boundary
    `exploit_trainer.plan_with_budget` crosses too (new `--has-public-exploit`/`--poc-url` CLI
    flags) -- so when a CVE is already known to have a real public exploit, the generated
    script now leads with an explicit notice pointing at that real PoC and naming exactly why
    the generic per-class template below it may not apply, instead of presenting a plausible-
    looking but wrong script as if it were this CVE's actual technique. Verified end-to-end
    through all three paths (`develop_exploit` directly, `plan()`'s no-binary path exactly as
    `investigate_cve` calls it, and the real `binoracle cveplan` CLI subprocess) using this
    exact CVE-2021-3156 scenario. Tests added to `tests/test_tools_and_config.py` for all three.
  - Third follow-up quality fix, same investigation: the notice above only fires when the
    caller already KNOWS a public exploit exists (`has_public_exploit=True`). But the
    `heap-overflow`/`uaf`/`double-free` template's CTF-menu assumption (`alloc`/`free`/`show`
    over stdin) is misleading for ANY real-world CVE investigation, not only one that happens
    to have an indexed public PoC already -- a freshly-disclosed heap CVE with no PoC on
    exploit-db/GitHub yet would still get the same confident-looking menu skeleton with zero
    caveat. Added a short, ALWAYS-present structural caveat right in the template itself
    (independent of `has_public_exploit`): it names the menu assumption explicitly and says a
    real program's actual trigger is more likely argv, a network request, a file, or an
    environment variable -- so the skeleton reads as "the common case for this vuln class,
    adapt the wrappers" rather than "the technique". Test added to
    `tests/test_tools_and_config.py` confirming the caveat is present with no known public
    exploit (the gap this closes) and that it doesn't collide with the conditional notice
    above.
  - Fourth follow-up, generalizing the same gap: audited every other `develop_exploit`
    template (`oob-write`, `integer-overflow`, `type-confusion`, the generic fallback) and
    every `webexploit.py` web-class builder (sqli, xss, ssrf, rce, path-traversal,
    file-upload, deserialization, xxe, ssti, open-redirect, csrf) for the same kind of
    confidently-wrong assumption the heap template had -- none had it: they're already
    minimal skeletons with explicit TODOs, or (the web builders) already build from the
    LLM's grounded hypothesis rather than a hardcoded guess. One real remaining gap, shared by
    EVERY `develop_exploit` template (not just heap): all of them use
    `io.sendline(payload)` against `io = process(BINARY)`, silently assuming the payload
    arrives over stdin -- wrong for a real CVE triggered via argv, an environment variable, a
    file, or a network request. Added one caveat line to `_dev_header` (shared by every class
    branch) naming the assumption and the argv alternative (`process([BINARY, payload])`),
    so every template carries it without repeating it per class. Test added confirming every
    non-web vulnerability class's template carries it.
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
- **[M] Fuzzing integration.** Audited first: `workflows/autofuzz.py` only tries a short fixed
  list of KNOWN vulnerability-shaped payloads (cyclic patterns, `%p`/`%n`, extreme integers) --
  no real coverage feedback, no mutation engine; `workflows/fuzz.py` only prints a harness
  template or an afl-fuzz command LINE for the human to run themselves. Neither is "drive
  AFL++... coverage-guided". Shipped now: `workflows/autofuzz_afl.py` -- actually BUILDS (with
  `afl-clang-fast`, given the C source) and RUNS `afl-fuzz` for a real time budget, then feeds
  every crash it saves back into `dynamic_dbg.DebuggerOracle`'s `dbg_run_input` for confirmation
  (registers + backtrace from a real gdb/lldb run, not just "afl said SIGSEGV"). Verified
  end-to-end against `samples/src/ret2win.c`'s unbounded `gets()`: afl-fuzz found a real
  SIGSEGV-crashing input via genuine coverage-guided mutation in under 30s, and binoracle's own
  gdb oracle reproduced and confirmed it (the crash backtrace even showed `win()`, a bonus
  signal of RIP control). A real snag hit and fixed: this project's own intentionally-vulnerable
  sample corpus uses classic unsafe calls (`gets()`) that modern clang treats as a hard
  `-Werror`-class failure (not a mere warning, so `-w` alone doesn't help) under its default C
  standard -- fixed by building with `-std=gnu89`, matching the old-C assumptions these samples
  were written against. Black-box/QEMU mode (`afl-fuzz -Q`, binary only, no source needed) is
  implemented too, but degrades honestly as NOT_APPLICABLE here: confirmed live that the stock
  Ubuntu `afl++` package does not ship `afl-qemu-trace` built, so that path needs either a
  source file (the instrumented path this increment actually verified) or the user building
  AFL++'s own QEMU support themselves. Wired into `binoracle fuzz --run` (CLI, alongside the
  existing template-printing default) and as its own MCP tool, `autofuzz_afl`.
- **[M] Stripped-binary function ID.** Audited first: nothing resembling FLIRT/BinDiff/signature
  matching existed anywhere in the codebase (`patchdiff.py`'s radiff2 wrapper diffs two binaries
  structurally but never recovers a NAME). Shipped: `workflows/funcid.py`, `identify_stripped_functions
  (stripped_binary, reference_binary)`. radare2 is the oracle (same convention as
  `patchdiff.py`'s radiff2 use): it lists functions (`aflj`) and disassembles each one
  (`pdfj @ addr`, whose `ops[].disasm` already carries RESOLVED call-target names); this module
  never invents a function body. The signature is two-tiered: (1) high confidence -- the ORDERED
  list of resolved import-call names (`sym.imp.*`) a function calls. This survives `strip`
  entirely, because a dynamically-linked ELF's `.dynsym` (needed at runtime to resolve
  `puts`/`system`/etc through the PLT) is a *different* table from `.symtab` (local symbols,
  what `strip` actually removes) -- so library-call names stay visible in a stripped binary even
  though local function names become `fcn.XXXXXXXX`. (2) fallback, heuristic-only, labelled
  `"similar"` and never `"exact-calls"` -- a plain `difflib.SequenceMatcher` ratio over mnemonic
  sequences, used only when a function calls nothing resolvable (confirmed live this signal alone
  is weak: 0.53 vs 0.48 for a true vs. an unrelated match on a short function, not a safe margin
  on its own). Verified end-to-end against a genuinely harder case than "a binary vs. its own
  stripped copy" (which would trivially match by address): `samples/src/ret2win.c` rebuilt at
  `-O1` and stripped, compared against the existing `-O0` unstripped `samples/bin/ret2win` as the
  named reference. `win()`'s prologue/epilogue changed completely under `-O1` (gained `endbr64`,
  lost its `push rbp`/`pop rbp` frame, moved address), but its call signature
  (`[sym.imp.puts, sym.imp.system]`) matched EXACTLY and uniquely against every other function in
  the stripped target -- recovered as `exact-calls`, score 1.0, no ambiguity. Degrades honestly:
  no radare2 installed, or a reference binary with no named functions to compare against, returns
  `ok=False` with a clear note rather than guessing. A real snag hit while prototyping (fixed
  before landing in the final module): `pdj %d @ addr` treats its first argument as an
  INSTRUCTION count, not a byte count, so passing a function's byte `size` there over-disassembles
  past its real boundary -- the final module sidesteps this entirely by using `pdfj @ addr`
  (disassembles the whole recognized function body at once, no count ambiguity). Covered by real
  tests in `tests/test_smoke.py`: the harder -O1-stripped-vs-O0 recovery case (compiled on the
  fly), a negative control (reference with no named functions -> clean `ok=False`, no invented
  match), and a degrade-cleanly-without-radare2 case. Wired into `binoracle funcid <stripped>
  <reference>` (CLI) and the web UI's `funcid` command.
- **[S] More formats & backends.** ~~A Ghidra-headless decompilation backend~~ (shipped:
  `callertools.py` drives `analyzeHeadless`) ~~and the capstone fallback oracle~~ (shipped:
  `oracles/capstone_fallback.py`, registers only when radare2 itself is unavailable) were already
  done. Audited: Go binary heuristics already existed (`goinspect.py` reads the embedded
  build-info blob); nothing existed for raw shellcode (no-container blobs) or Rust. Shipped both:
  - ~~Raw shellcode analysis~~: `workflows/rawshellcode.py`, `analyze_raw_shellcode(data)`.
    capstone (same dependency `capstone_fallback.py` already needs) tries EVERY architecture it
    knows how to decode x86/ARM/MIPS shellcode in and ranks the candidates heuristically (bytes
    consumed as valid instructions, penalized for classic "decoded non-code as x86" noise
    mnemonics like `das`/`aad`, rewarded for an actual `syscall`/interrupt instruction present) --
    per this project's "no false positives by construction" rule, it NEVER asserts a single
    architecture, only a ranked list with scores shown. Verified against this project's own real
    amd64 `execve("/bin/sh")` shellcode (`workflows/shellcode.py`'s precompiled blob): x86-64
    correctly ranks first (score 1.2) over x86-32 (1.16, same bytes decode as "valid" but with
    `das`/BCD-arithmetic noise) and ARM/ARM64/MIPS (which fail to consume most of the bytes at
    all); the `syscall` instruction and the embedded `/bin//sh` string are both surfaced.
  - ~~Rust binary heuristics~~: `workflows/rustinspect.py`, `inspect_rust(path)`, the Rust
    counterpart to `goinspect.py`. Rust has no build-info blob like Go's, but rustc bakes the full
    source path of every library it compiles into panic-location strings:
    `/rustc/<40-hex-commit>/library/...` for std, `/rust/deps/<crate>-<version>/...` for Cargo
    dependencies -- plain ASCII in `.rodata`, so (confirmed live) they SURVIVE `strip` entirely,
    unlike mangled symbol names (checked as a secondary, lower-confidence signal only). Verified
    end-to-end: compiled a real `rustc -O` binary, `strip`-ped it, and recovered the exact rustc
    commit hash plus its Cargo dependency crates (`addr2line`, `gimli`, `miniz_oxide`) from the
    stripped binary; a real C binary (`ret2win`) correctly reports no Rust signal. Wired into
    the unified `identify()`/`binoracle identify` path (ELF routing now tries Go, then Rust,
    before falling back to the generic ELF layout reader) so it is picked up automatically, not
    only via its own explicit command.
  Both are covered by real tests in `tests/test_smoke.py` (positive cases against real compiled/
  stripped binaries, a negative control, and a clean degrade when the dependency -- capstone, or
  rustc+strip for the test's own fixture build -- is missing), and wired as their own MCP tools
  (`analyze_raw_shellcode`, `inspect_rust_binary`) and CLI subcommands (`binoracle rawshellcode`,
  `binoracle rust`).

## v0.5 - Product, trust, workflow

- **[M] Regression dashboard.** Audited first: `store/session.py`'s `SessionStore` already
  persists the CURRENT state of a binary's findings (keyed by content-hash `bin_id`, upserted in
  place on re-analysis) and `web.py` already has a multi-target history list (the sidebar "H"
  button) -- so "persistent multi-target web UI" already existed. What was missing, and is the
  point of this item, is "diff-between-runs": there was no history of PAST states to diff
  against (upsert overwrites in place), and content-hash is the wrong key for it anyway -- a
  patch changes the hash, so re-scanning the same logical target after a fix would land on a
  *different* `bin_id` row instead of accumulating history on the same one. Shipped:
  `store/runs.py`, keyed by the TARGET PATH (the string handed to `audit`, stable across builds)
  instead of content hash. `record_run(db_path, target, findings)` snapshots the current finding
  set as a new row every time `run_audit` finishes (wired into `workflows/audit.py`, right after
  the existing `save_verified_facts` curation step) -- each audit of the same target accumulates
  one more point in its history, even as the underlying binary changes. `diff_latest_two` compares
  the two most recent runs and classifies every finding key (title+location) into one of three
  GROUNDED categories (never inferred): `new` (never appeared before the previous run),
  `reintroduced` (absent from the previous run but present in an OLDER one -- fixed once, came
  back), `fixed` (was in the previous run, gone from the latest). Verified end-to-end against a
  real `SessionStore` (not synthetic dicts): three simulated audit runs on the same target path --
  run 1 has findings A+B, run 2 has A + a new C (B "fixed" by deleting its row, as a real
  re-analysis would), run 3 brings B back -- correctly classifies C as `new` in the first diff and
  B as `reintroduced` (not `new`) once it returns. Covered by real tests in
  `tests/test_tools_and_config.py` (the three-run classification above, plus a degrade-cleanly
  case for fewer than 2 runs). Wired into `binoracle runs [target] [--diff]` (CLI), two MCP tools
  (`regression_targets`, `regression_diff`), and the web UI's dispatcher (`runs_targets`/
  `runs_diff` commands) -- same dispatcher-only integration `regress`/`funcid` already use, no
  dedicated catalog panel yet (same as those two).
- **[M] CI action.** Audited first: `run_audit` (the LLM agent loop) is the wrong engine for a
  generic CI runner -- it needs a local LLM backend reachable, which most CI runners simply don't
  have. `workflows/regress.py`'s `run_regress` already runs the grounded pipeline (triage + hunt
  + angr verification) with `llm=None` between an OLD and a NEW build -- confirmed live it
  genuinely works with zero LLM backend configured. Shipped: `workflows/ci_gate.py`,
  `run_ci_gate(old, new, config, gen_test=False)` -- the missing PASS/FAIL verdict layer on top
  of `run_regress`'s diffs (and, with `gen_test=True`, `autoregress_test`'s real exploit
  re-verification). Deliberately narrow about what fails the build: a NEW finding only fails if
  its verdict is `verified` (not merely `grounded`/`unverified`); a verdict escalating TO
  `verified` on an existing finding fails too; a mitigation change only fails if it WEAKENS
  something that was on (`True -> False`) -- turning a protection ON must never fail a build, only
  turning one OFF; and (with `--gen-test`) any autopwn technique that verified on OLD and STILL
  verifies on NEW is the strongest possible signal and always fails. Verified end-to-end against
  real fixtures: `ret2win` (vulnerable) vs. `ret2win_patched` (same source + a canary) correctly
  PASSES (adding a protection is a fix, not a regression); `ret2win` vs. itself, WITH
  `--gen-test`, correctly FAILS with the exact reason (`ret2win` still verifies on NEW) -- not a
  vacuous pass just because the pipeline could re-run. Wired into `binoracle ci-gate <old> <new>
  [--gen-test]` (CLI) with a real process exit code (0 pass / 1 fail / 2 pipeline error, so a
  shell `&&`/`if` or a CI step's own failure detection just works), and into an actual
  distributable **`action.yml`** at the repo root (a composite GitHub Action other repos can
  reference as `uses: beafn28/binoracle@<ref>` with `old`/`new`/`gen-test` inputs) that installs
  radare2 + binoracle, runs the gate, writes the report to the job summary, and fails the step on
  a non-zero exit -- the actual "fails a PR" mechanism the ROADMAP line asks for, not just a
  library function. Covered by real tests in `tests/test_smoke.py`: the real pass/fail cases
  above, plus a unit test confirming a mitigation being STRENGTHENED alone never trips the gate.
- **[L] Cross-engagement knowledge base.** Audited first: most of "attack PATTERNS, anonymized,
  across targets" already existed and is already CONSUMED, not just written --
  `store/session.py`'s `global_facts` (anonymized verified findings keyed by arch/sink, read
  back via `relevant_facts()` and fed into the agent's own prompt in `workflows/audit.py`) and
  `exploit_skill` (per arch/class/strategy attempts+successes, read and updated by
  `workflows/exploit_trainer.py`) already make this true for findings and exploit strategies.
  What was genuinely missing is literal GADGET reuse: `workflows/chainanalyzer.py`'s
  `_enum_gadgets` runs a full ROP scan of `.text` via radare2 (`/Rj` per pattern) that its own
  comment already flagged as expensive -- "~6s EACH... ~17 patterns = ~110s" on an 800KB static
  binary (hence the existing `BINORACLE_GADGET_BUDGET` time-box). Shipped: `store/gadget_cache.py`,
  wired straight into `_enum_gadgets`. Keyed by the exact SHA256 of the scanned binary's content
  (same hashing `store.session.binary_id` already uses) -- NOT a similarity heuristic, so a false
  hit is structurally impossible: two targets (a repeated challenge binary, or two different
  targets that statically embed the same libc/musl `.text`) only ever share a cache entry when
  their scanned bytes are byte-identical, in which case the gadgets genuinely ARE identical.
  Anonymized by construction: the cache stores the content hash and the gadget list (addresses +
  instruction text), never the original path or filename. Verified end-to-end against a real
  fixture (`samples/bin/ret2win`): the real r2 scan took ~6s on the first call; a second call on
  the identical binary returned the SAME gadgets (same addresses, same instruction text) in
  effectively 0s with radare2 never invoked again (confirmed by spying on the r2 session
  getter -- zero calls on the cache hit). Degrades honestly: if the cache itself fails to read or
  write for any reason, `_enum_gadgets` still falls through to the real scan rather than returning
  an empty/stale result. Covered by real tests in `tests/test_smoke.py`: the cache-hit-skips-r2
  case above, and a degrade-cleanly case with the cache forced to raise on every call.
- **[M] Model quality.** Prompt-tuning for the agent loop and a planner+verifier multi-model
  split remain open -- both need a live local LLM to iterate against and verify honestly,
  and this environment has none reachable (confirmed: `ollama` down, and `ollama.com`/
  `registry.ollama.ai`/`huggingface.co`, every source of model weights or the ollama binary
  itself, are all blocked by this environment's own egress policy -- not something to work
  around, a real constraint of where this ran).
  - ~~Better native tool-calling for capable local models.~~ Shipped, and fully testable
    without a live model (every test below drives a real `AgentLoop` end-to-end against a
    fake backend, or a real `OllamaBackend`/`OpenAICompatBackend` against a faked HTTP layer
    -- never a live network call). `binoracle/llm/base.py`'s `chat()` gained an optional
    `tools` parameter (an OpenAI-style function-calling schema); `OllamaBackend` and
    `OpenAICompatBackend` send it as native `tools` (Ollama's `/api/chat` `tools` field /
    OpenAI `tools`) ONLY when both the backend supports it and `config.native_tools` is
    explicitly turned on (`BINORACLE_NATIVE_TOOLS=1`) -- deliberately opt-in, never
    auto-detected, since native tool-calling only works well on SOME local models (Llama
    3.1+, Qwen2.5+, others tagged "tools" in `ollama show`) and the project has no cheap, safe
    way to probe which from here. Critically, this does NOT introduce a second, parallel
    protocol: when the model's own function-calling layer returns a native tool-call, the
    backend converts it back into the EXACT SAME portable JSON text
    (`{"name": ..., "arguments": {...}}`) `agent/tools.py`'s `extract_action` already parses,
    so `AgentLoop`'s own anti-repeat/anti-spam/gating logic and every other `chat()` consumer
    are completely unaffected -- native tool-calling only changes how the model is ASKED to
    act (its own structured function-calling instead of hoping free text happens to parse as
    JSON), never the shape `chat()` hands back. `AgentLoop._native_tool_schema()` builds the
    schema from the live `ToolRegistry` plus a synthetic `finish` tool (native tool-calling
    has no other way to signal "I'm done" distinct from "call this tool"); calling `finish` is
    mapped back to the exact same final-answer path the portable protocol already uses.
    Verified end-to-end with fake/faked backends: a native tool call drives the real target
    tool, a native `finish` call ends the loop with the right answer, the tool schema sent to
    the backend includes both the real tools and `finish`, and -- the regression that caught
    a real bug while building this -- passing `tools=` unconditionally to every backend's
    `chat()` broke any backend/test-double written before this parameter existed (a
    `TypeError: unexpected keyword argument 'tools'`); fixed by only including the `tools`
    kwarg at all when native tool-calling is actually in play. Confirmed off by default: with
    `native_tools` unset, `chat()` never even receives a `tools` kwarg, so a backend whose
    `chat()` predates this feature entirely keeps working unchanged. 7 tests added to
    `tests/test_smoke.py` covering all of the above.

## Cross-cutting quality (ongoing)

- ~~Type hints + mypy, `ruff` lint, and a coverage gate in CI.~~ First increment shipped.
  `[tool.ruff]`/`[tool.mypy]` added to `pyproject.toml`: the ruff gate is deliberately narrow --
  `select = ["F"]` (pyflakes only: unused imports, undefined names, unused variables, pointless
  f-strings), confirmed at zero across the whole codebase. Broader style/modernization rulesets
  (line length, import sorting, py3-upgrade rewrites) found thousands of pre-existing hits across
  this codebase's history and are deliberately deferred rather than mass-mechanically
  "fixed" -- enforcing those now would mean either a risky mechanical reformat or ignoring real
  findings just to get a passing gate; broadening the ruleset is future "ongoing" work, done
  rule-by-rule with the same scrutiny. A real regression was caught and fixed while reaching that
  zero: ruff's own `--fix` for "unused import" silently deleted TWO deliberate `try: import X ...
  except: _HAVE_X = False` availability probes (`oracles/capstone_fallback.py`'s r2pipe check and
  `workflows/autopoc.py`'s angr check) -- the import's NAME is never referenced again by design
  (only its potential `ImportError` matters), which a plain unused-import check can't tell apart
  from a genuinely dead import; confirmed live that after the auto-fix `_HAVE_R2PIPE`/`_HAVE_ANGR`
  were stuck at `True` even without r2pipe/angr installed, since the try block could no longer
  fail. Restored both with an explicit `# noqa: F401`, and added a regression test
  (`tests/test_smoke.py`) that parses both files' ASTs and asserts the real import sits inside the
  `try` next to the flag it guards -- so a future "cleanup" can't silently reintroduce this bug.
  mypy is wired in as ADVISORY, not a hard gate yet: a first `--ignore-missing-imports` pass over
  this ~15k-line, mostly-untyped codebase found ~400 pre-existing errors across ~70 files (a few
  look like genuine latent bugs worth triaging later, most are missing-annotation noise) --
  burying a brand-new CI gate under 400 failures on day one would just get it disabled, so CI runs
  it and reports the count without failing the build; promote files to a hard per-module gate as
  they get cleaned up. The coverage gate (`pytest --cov=binoracle --cov-fail-under=N`) is real and
  enforced from day one, deliberately started at a conservative floor (20%) rather than the
  measured value -- this codebase's own test suite is slow enough (many tests drive real
  sandboxes/angr/docker/Wine) that a full coverage run didn't finish before this increment shipped;
  raise it to the real measured number (with headroom) once that run completes. All three are
  wired into `.github/workflows/ci.yml`.
  - Audited, NOT applied: `pytest-xdist` (`-n auto`) as a fix for the slow-suite problem named
    above. It's already an installed dependency and looks like a free, low-risk win on paper --
    the suite is mostly independent test files, and a quick check confirmed no fixed ports or
    named Docker containers that would collide across workers (every socket test binds port 0,
    every Docker test lets the daemon assign a random container name). But two separate live
    attempts to run the full suite with `-n auto` in this environment did NOT complete cleanly:
    one stalled around 93-97% with no worker processes left alive and no final summary; a
    second attempt WITH `-x` (meant to abort fast on the first failure) still didn't exit within
    280s, consistent with xdist's own limitation that `-x` can only stop scheduling new tests,
    not interrupt whichever slow test is already running in another worker. Most likely cause:
    this suite runs real Docker containers and real angr symbolic execution directly (per the
    comment above), and 4 of those competing for memory/CPU at once behaves very differently
    from one running at a time. Conclusion: `-n auto` is not the safe drop-in it looks like for
    THIS suite without first identifying and isolating (or serial-only marking) the handful of
    heavy sandbox/angr tests -- real work, not worth it for a workflow that's `workflow_dispatch`
    only (zero ongoing cost pressure; see the item above). Left `ci.yml` as plain serial pytest.
    Revisit with a bounded worker count (`-n 2`) and/or `pytest.mark.serial` on the Docker/angr
    tests specifically, if the full-suite runtime ever becomes an actual blocker.
  - Follow-up: found the ACTUAL root cause of the slow/apparently-hanging full-suite runs above
    (a manual `ci.yml` run was left running 4+ hours with no sign of finishing before being
    cancelled). It was never the lack of parallelism or genuinely stuck `r2session.cmd_timeout`
    machinery (that machinery's own daemon-thread-join-then-kill design turned out to be sound):
    it was `tests/test_smoke.py::test_pe_inspect_on_real_pe_if_present`, which used
    `glob.glob(os.path.join(root, "**", "*.dll"), recursive=True)` (and `*.exe`) over `/usr` and
    `/opt` to find a real PE file to sanity-test `inspect_pe` against, then sliced `[:50]` --
    but the slice happens AFTER `glob.glob` returns, so it has to finish walking the ENTIRE tree
    first. In a container with a full `/usr` (every Python package, every doc/locale file, plus
    r2/angr/Docker's own installed footprint), that unbounded recursive walk is slow enough to
    plausibly explain hours, not minutes. Two real fixes landed together: (1) `pytest-timeout`
    was an installed dependency in some environments but never a DECLARED dependency nor
    configured anywhere -- added `pytest-timeout>=2.3` to the `dev` extras and a
    `[tool.pytest.ini_options]` with `timeout = 300` (`timeout_method = "thread"`, since this
    suite's own real subprocess/thread use doesn't play well with signal-based interruption) in
    `pyproject.toml`, set comfortably above every known-legitimate slow operation
    (`r2session.py`'s own internal 180s/90s timeouts) so it only fires on a genuine hang, not a
    merely-slow test -- this is what actually caught the glob bug live (300s timeout tripped
    mid-walk) instead of it staying silently undiagnosed. (2) Rewrote the test itself to use a
    directory-count-capped `os.walk` that stops at the FIRST real PE found, instead of
    enumerating the whole tree twice per directory -- confirmed live: 4+ minutes (hit the new
    300s cap) down to 4 seconds. Caught and fixed a real mistake made while editing this: the
    first edit to add `[tool.pytest.ini_options]` accidentally deleted the `[tool.ruff]` table
    header line it was inserted next to, silently reparenting `line-length`/`target-version`
    under the wrong table (confirmed via a `PytestConfigWarning: Unknown config option` pytest
    itself emitted) -- caught before anything was pushed, fixed, and reverified (`ruff check
    binoracle` clean, TOML re-parses correctly) rather than shipped broken. Verified end to end:
    the fixed test (4s), then the full `test_smoke.py`/`test_autoheap.py`/`test_rag.py`/
    `test_sandbox.py` regression subset (199 passed, 6 skipped, 0 failed, ~8 min, no hangs).
- ~~Quieter optional dependencies (pwntools/angr logging), graceful-degradation everywhere.~~
  angr, which IS imported straight into this process (`oracles/symbolic_angr.py`,
  `oracles/concolic.py`, `workflows/autopoc.py`), had real duplication: three separate copies of
  the same `getLogger(...).setLevel(ERROR)` block, one of them (`symbolic_angr.py`) missing
  `pyvex` entirely (quieting `angr`+`cle` only). Factored into a shared `binoracle._quiet_angr()`,
  now used by all three (and automatically covers `pyvex` everywhere). `binoracle/__init__.py`
  also has a `_quiet_pwn()` helper for the small number of workflows that build a pwntools chain
  / PoC snippet directly in THIS process (`rop.py`, `shellcode.py`, `fmtstring.py`, `autopoc.py`,
  and now `autofuzz.py`'s `_cyclic` too, added here for the same consistency); every OTHER
  exploit workflow instead builds a driver SCRIPT (a separate `from pwn import ...` string) that
  runs as its own subprocess and quiets itself inline via `context.log_level = "error"`, since
  `_quiet_pwn()` can only run in the process it was imported into. A real mistake was made and
  caught mid-session: an initial pass concluded `_quiet_pwn()` was dead (grepped only for
  TOP-LEVEL, column-0 `from pwn import` and missed the four indented host-process call sites
  above) and deleted it -- confirmed broken not by static analysis but by actually running
  `binoracle autopwn` against a real sample (`samples/bin/canleak`) and seeing its `rop-chain`
  combo report `pwntools no disponible: cannot import name '_quiet_pwn'` instead of a real
  reason. Restored immediately, with a test (`test_quiet_pwn_has_real_host_process_callers`)
  confirming `rop.py` genuinely detects pwntools again. Graceful-degradation audit: every oracle
  file already guards its optional import with `try/except` (no bare unguarded `import` found
  across `oracles/*.py`) -- already solid, no gap found there. Covered by real tests in
  `tests/test_smoke.py`: `_quiet_angr` confirmed to pin all three loggers to ERROR, an AST-based
  check that all three angr-importing modules call the shared helper, and the restored
  `_quiet_pwn` coverage above.
- ~~A docs site with a guided tutorial over the `samples/` corpus.~~ Shipped `docs/TUTORIAL.md`:
  a progressive, hands-on walkthrough of the practice corpus -- `triage` first (grounded facts,
  no execution), then `ret2win` (no canary, verified), `canleak` (canary ON but with a genuine
  leak -- the right bypass technique is chosen automatically because the canary is detected,
  verified), `fmtstring` (no gift function at all, format-string GOT overwrite to a shell,
  verified), and an HONEST heap negative (`notes_heap` under the generic heap prober genuinely
  doesn't trigger with its fixed test inputs -- the tutorial explains why that's the CORRECT
  behavior, not a bug, and points to the dedicated per-technique heap fixtures that DO verify).
  Every command's output in the tutorial is copy-pasted from an actual run against the real
  compiled sample, not invented. Shipped `docs/build_site.py`: an actual static-site generator
  (needs only the `markdown` package, no server/JS) that renders the tutorial plus `USAGE.md`/
  `ENGINE.md`/this file into real, navigable HTML with a shared nav sidebar -- `python3
  docs/build_site.py` writes `docs/site/*.html`, openable directly in a browser. Verified
  end-to-end: ran the generator for real and parsed every one of its 5 output pages with a
  strict HTML parser (catches malformed markup, not just "the script didn't crash"), and
  confirmed the tutorial page's rendered HTML actually contains its real verified-exploit
  content. Covered by a real test in `tests/test_smoke.py` doing exactly that. `docs/site/` is
  a build artifact (gitignored), not committed -- rebuild it whenever a source `.md` changes.
- ~~Dynamic n-day verification for CLI-tool filename-driven command injection, with no network
  endpoint at all.~~ First shipped against a real, current CVE rather than a guessed shape --
  CVE-2025-64756 (`glob` npm CLI, GHSA-5j98-mcp5-4vw2): `-c`/`--cmd` passes matched filenames to
  a shell with `shell: true`, so a crafted filename (e.g. `` $(touch injected) ``) executes
  arbitrary commands. Every existing `investigate_cve` verifier (`wpverify.py`/`drupalverify.py`/
  `joomlaverify.py`/`genericverify.py`) was built around `notes.get("endpoint")` -- an HTTP
  request sent to a running service -- which this vulnerability shape has none of: the "request"
  is a local filename, there's no server to spin up a lab against. First investigated and
  audited here as a deliberately-deferred gap, then actually built once asked to: a NEW,
  narrowly-scoped verifier, `workflows/cliverify.py`'s
  `verify_cli_filename_command_injection(setup_cmd, run_cmd, ...)` -- no Docker, no network, no
  session: a disposable `tempfile.mkdtemp()` work dir, a file whose NAME IS the payload
  (`$(touch <canary>)`), the tool run exactly as an analyst would, and a canary-file check
  (never a deduction from exit code/stdout). Reproduced for real, locally and disposably (an
  isolated `/tmp` npm install of the real vulnerable `glob@11.0.0`, nothing touching a real/
  production system): `verified=True` with the injected file actually present. Negative control
  against the real PATCHED version (`glob@11.1.0`) confirmed `verified=False` -- not a verifier
  that just always says yes. Wired into `cve_agent.py`'s dispatch (`_run_web_investigation`,
  right after `notes = inv.llm_notes or {}`, returning early): reuses the existing
  `command-injection`/`os-command-injection` vuln_class (a new invented label would never win --
  `classify_cve(inv.description)` is tried before any analyst hint when `inv.vuln_class` is
  assigned), gated instead on two new hints, `cli_setup_cmd`/`cli_run_cmd` (new `--cli-setup-cmd`/
  `--cli-run-cmd` CLI flags), since those are what actually distinguishes "no endpoint, a local
  tool" from the web case -- confirmed end-to-end for real via `binoracle investigate
  CVE-2025-64756 --cli-setup-cmd "npm install glob@11.0.0" --cli-run-cmd '...' --no-cache`:
  "Estado: VERIFICADO en sandbox".
  That same end-to-end run surfaced a SECOND real, broader honesty bug while reading the
  rendered report: the "Evidencia real de la ejecucion" section hard-coded the WordPress
  account-takeover evidence shape (`login_bajo_privilegio`/`admin_user`/...) and an unconditional
  caption claiming "contra el WordPress desechable de arriba" -- for ANY other verified class
  (command-injection/SQLi/SSRF/SSTI/path-traversal across wpverify.py/drupalverify.py/
  genericverify.py, dozens of real call sites that set `evidence["payload_ganador"]`) the report
  showed literally NOTHING of the real proof, or worse, composite `None` strings (the old filter
  `value not in ("None", "`None`")` never caught `` `None` (id=None) ``) under a false "WordPress"
  claim -- for this CLI CVE specifically it rendered "Usuario de bajo privilegio: `None` /
  `None`" for a target that was never WordPress, never had a login at all. Fixed generically:
  the caption no longer names any CMS, the row list is now built conditionally per the KEYS
  actually present in `evidence` (WordPress account-takeover shape / HTTP request+status shape /
  the new CLI shape), a new row surfaces `parametro_ganador`/`payload_ganador` whenever present
  (the fix with the widest blast radius -- every command-injection/SQLi/SSRF/SSTI/path-traversal
  verifier across all three CMS-specific modules plus the generic one gets its real winning
  payload shown for the first time), and the `None`-filter now rejects any row whose rendered
  value contains "None" anywhere, not just an exact match. Covered by 5 new tests in
  `tests/test_tools_and_config.py`: the verifier against a self-contained offline repro of the
  exact bug shape (no network needed for CI: an `eval` over shell-globbed filenames, not the
  real npm package) with both a positive and a safely-quoted negative control, a setup-failure
  path, the full dispatch+render path for the CLI case, and a render test proving the
  `payload_ganador` row now appears for a non-WordPress verified class with zero WordPress-shaped
  fields.
  Deliberately still narrow: covers exactly the proven shape (a crafted FILENAME reaching a
  shell via `shell: true`), not a generic "any CLI tool" framework -- if payload-in-an-argv-VALUE
  (rather than a filename) turns up as a second real confirmed case, it gets added with the same
  "poco a poco" discipline, not guessed ahead of time.
- Dynamic n-day verification for a THIRD form of WordPress missing-authorization, distinct from
  the two `wpverify.py` already had (`verify_wordpress_account_takeover`: an authenticated
  low-privilege session changes another user's credential by ID; `verify_wordpress_direct_login_as`:
  an authenticated low-privilege session impersonates another user by ID) -- grounded in a real,
  current CVE, not guessed: CVE-2026-2991 (KiviCare for WordPress,
  `AuthController::patientSocialLogin`, `POST /wp-json/kivicare/v1/auth/patient/social-login`,
  `permission_callback => '__return_true'`). Read the real plugin source (downloaded straight
  from the official wordpress.org SVN/API, both the vulnerable 4.1.2 and the patched 4.1.3) to
  confirm the exact mechanism: the handler looks up an existing user by email/phone and, if
  found, calls `wp_set_auth_cookie($user_id)` with ZERO validation of the "access_token" it
  claims to check -- anyone who knows a registered patient's email is logged in as them, no
  password or real token needed at all. The patched version simply deletes the endpoint. Shipped
  `verify_wordpress_unauthenticated_login_bypass(plugin_source_dir, slug, endpoint, http_method,
  parameters, email_param_hint, victim_role="subscriber", ...)` in `wpverify.py`: unlike the two
  existing techniques, it needs NO prior session at all -- attacks with a brand-new anonymous
  `requests.Session()`, creates its OWN victim user (not the shared bootstrap subscriber, since
  some plugins including this one only accept a role they define) with a known email, and
  confirms via a SEPARATE, independent page the attacked endpoint never touches
  (`/wp-admin/profile.php`, cookie-only auth, no REST nonce involved at all) that the real email
  of that exact victim shows up -- never a deduction from the attacked endpoint's own status
  code, which this CVE's own plugin proves can mislead: it returns 403 ("not a patient account")
  AFTER already calling `wp_set_auth_cookie`, so the real compromise happens regardless of that
  403. First proof mechanism attempted (`/wp-json/wp/v2/users/me` + a nonce scraped from the
  attacked endpoint's own JSON response) was found live, while writing this verifier's own test,
  to be fragile: that REST endpoint demands a valid `X-WP-Nonce` even with a correct session
  cookie (anti-CSRF), and a nonce only comes out correctly formed in the response if the
  attacked plugin does a specific trick (rewriting `$_COOKIE[LOGGED_IN_COOKIE]` mid-request
  before calling `wp_create_nonce`) that KiviCare happens to do but nothing guarantees any other
  vulnerable plugin will -- would have produced a FALSE NEGATIVE against an equally-real bypass
  on a plugin that doesn't do that trick. Switched to the admin profile page instead (same
  cookie-only pattern `verify_wordpress_direct_login_as` already uses), which needs no nonce at
  all. A second real, generalizable infrastructure gap surfaced along the way and was fixed at
  the SHARED bootstrap level (`_bootstrap_lab`, used by every WordPress dynamic verifier, not
  just this one): a fresh `wp core install` leaves permalinks on "plain" (`?p=123`), under which
  `/wp-json/...` REST routes (the pattern newer plugins increasingly use instead of the older
  `admin-ajax.php`) silently return the homepage HTML with a 200 instead of routing at all --
  every real WordPress CVE this project had verified before this one happened to be
  `admin-ajax.php`-based, which works under any permalink structure, so this had never been hit.
  Fixed by running `wp rewrite structure '/%postname%/'` + `wp rewrite flush` right after core
  install. Wired into `cve_agent.py`'s dispatch behind an explicit new hint,
  `unauthenticated_login_bypass` (`--unauthenticated-login-bypass`/`--victim-role` CLI flags) --
  never auto-detected from the parameter shape alone, since an email+password pair in the
  hypothesis could just as plausibly mean the EXISTING credential-change pattern; only an
  analyst who read the real advisory knows the endpoint is genuinely unauthenticated. Also
  widened that dispatch's vuln_class gate to include `auth-bypass` alongside
  `missing-authorization`/`idor`: a second real bug found live -- `classify_cve()` maps an
  advisory that literally says "authentication bypass" to its own `auth-bypass` category, which
  WINS over any `--vuln-class missing-authorization` the analyst passes by hand (`classify_cve`
  is tried on the real description first), so the whole branch was being skipped entirely before
  this widening, regardless of the new technique. Verified end-to-end for real: the real
  vulnerable 4.1.2 plugin (downloaded from wordpress.org, installed in an ephemeral WordPress+
  MySQL Docker lab) gives `verified=True`; the real patched 4.1.3 gives `verified=False` (404 --
  the route is simply gone). Confirmed through the actual CLI end to end too: `binoracle
  investigate CVE-2026-2991 --source <plugin.zip> --cms wordpress --version 4.1.2 --vuln-class
  missing-authorization --endpoint /wp-json/kivicare/v1/auth/patient/social-login --method POST
  --params "login_type=google,password=...,first_name=Attacker,email"
  --unauthenticated-login-bypass --victim-role kiviCare_patient` -> "Estado: VERIFICADO en
  sandbox". Covered by 2 new tests in `tests/test_tools_and_config.py`: a quick offline degrade
  case (no email param identifiable), and a LIVE test (skipped without Docker, matching the
  house convention for the other two WordPress techniques) against a SYNTHETIC minimal plugin
  reproducing the exact vulnerability shape plus a genuinely-fixed negative control (validates a
  real per-user secret token that no attacker can know) -- never downloads the real KiviCare zip
  in CI, which stays a manual, one-off investigation step.
  (One lab-only snag hit investigating the real plugin, never shipped: KiviCare 4.1.2/4.1.3's
  own `KCMigrator.php` references `KCScaffold::class` unqualified from inside the
  `App\database\classes` namespace, but the real class lives in `App\database\CLI` -- an
  authoring bug in the THIRD-PARTY plugin itself, unrelated to the CVE, that blocks `wp plugin
  activate` under WP-CLI; worked around with a one-line `use` import added to the LOCAL
  downloaded copy only, purely to stand the lab up, the same spirit as this session's earlier
  vendor-pip-install workarounds -- never touches anything binoracle ships.)
- Audited (not applied): dynamic n-day verification for SQL injection via ORM KEYWORD-NAME
  injection through dict expansion -- a fourth SQLi shape, distinct from the one
  `genericverify.py` already covers (`verify_generic_sqli_blind`: time-based, injects into the
  VALUE of a named parameter). Investigated against a real, current, framework-level CVE rather
  than guessing a shape: CVE-2025-64459 (Django, `QuerySet.filter()`/`.exclude()`/`.get()` and
  `Q()`, fixed in 5.2.8/5.1.14/4.2.26) -- `Q.__init__`'s `_connector` kwarg went straight into
  `WhereNode.connector` with zero validation before the fix (confirmed by diffing the real
  5.1.14 vs. 5.1.7 source, cloned from the official django/django repo), and
  `WhereNode.as_sql()` interpolates that connector RAW into the SQL text (`conn = " %s " %
  self.connector`, `where.py`) -- never parameterized, since it is structural glue between
  clauses, not a value. Any app using the documented-as-risky-but-real pattern
  `Model.objects.filter(**request.GET.dict())` (or any dict built from unvalidated request data)
  lets an attacker add a `_connector` key with a value like `") OR 1=1 OR ("` and bypass the
  entire WHERE clause. Reproduced for real, locally and disposably (two isolated venvs, real
  `pip install Django==5.1.0` and `Django==5.1.14`, a from-scratch minimal Django app/view
  written for this investigation using exactly that real-world pattern -- not a copy of the
  public PoC repo found while researching this, which was read for the confirmed payload shape
  but never executed): a baseline request for a nonexistent, non-admin user correctly returns
  nothing; the identical request plus `_connector=") OR 1=1 OR ("` against the real vulnerable
  5.1.0 dumps every row including the admin's `secret_token` field; the same request against the
  real patched 5.1.14 is rejected outright (`"The following kwargs are invalid: '_connector'"`).
  Deliberately NOT built into genericverify.py: the injection point is a dict KEY name reachable
  only via kwarg-unpacking into an ORM call, not an HTTP parameter VALUE reaching a SQL string --
  existing verifiers inject candidate SQL fragments into a value and look for a generic side
  channel (a canary file, a timing delay); this CVE's proof instead requires knowing which
  response rows are supposed to be absent for a given filter (an app-specific canary, not a
  generic file/timing oracle), and the vulnerability itself lives in the Django FRAMEWORK, not
  in a one-off third-party plugin -- the shape `investigate_cve`'s architecture (fetch a
  plugin/module's source, install it, attack it) is built around. A future verifier for this
  shape would need its own narrow contract: an endpoint, a baseline filter expected to match
  nothing, and a canary value expected to appear only on bypass -- closer to
  `verify_generic_idor`'s "known difference, not a generic oracle" shape than to the
  time-based/canary-file verifiers.

- Dynamic n-day verification for a Joomla extension whose own PHP code is too OLD to run inside
  this project's Joomla lab at all -- grounded in a real, current CVE: CVE-2025-40636
  (`mod_vvisit_counter` 2.0.4j3 / "Vinaora Visitors Counter", INCIBE-2025-0540, CVSS v4.0 9.3,
  unauthenticated SQLi via the `cip_vvisitcounter` cookie). Found and downloaded the real
  module source (no GitHub/SourceForge mirror exists; the Joomla Extensions Directory listing
  and the old `joomlacode.org` project page are both gone) via an Internet Archive snapshot of
  the original author's own download page (`mmajunke.de`), exact version `2.0.4j3`. Read the
  real `helper.php`: `modVisitCounterHelper::init()` computes the cookie name as
  `"cip_" . $this->s_createtableName_raw` (default `vvisitcounter` -> exactly
  `cip_vvisitcounter`, matching the advisory), `base64_decode()`s it with ZERO sanitization into
  `$this->callerIP`, then builds `"... WHERE ip=UNHEX(SHA1('$ip')) AND (...)"` and
  `"INSERT INTO ... VALUES ( ..., UNHEX(SHA1('$ip')), ... )"` by raw string concatenation --
  confirmed exactly where INCIBE's advisory said it would be, reachable with the module's
  factory-default settings (locktime>0, cookies on, not read-only) on every page it renders.
  First tried the obvious path -- install the real extension into `joomlaverify.py`'s existing
  Joomla 5 + MySQL 8 lab via the official `extension:install --path=<zip>` CLI, the same call
  the image's own entrypoint uses for `JOOMLA_EXTENSIONS_PATHS` -- and this closes a real open
  question the module's own docstring had been carrying since it was written: `extension:install`
  worked perfectly against this real third-party extension (manifest installed, `#__extensions`
  row created and already enabled). But the extension itself never got to execute its SQL: its
  `helper.php` calls `$db->query()`, `$db->Quote()`, `$db->getErrorNum()`, `$db->getErrorMsg()` --
  the legacy `JDatabaseDriver` API from Joomla <4.0 -- and the `joomla/database` Composer package
  that BOTH Joomla 4 and Joomla 5 ship removed every one of those method names (confirmed by
  grepping their own `DatabaseDriver.php`: only `execute()`/`quote()`, lowercase, remain). The
  module fatals with "Call to undefined method" on its very first database touch
  (`CREATE TABLE IF NOT EXISTS`), before the vulnerable `SELECT`/`INSERT` ever run. The
  Joomla version this module WAS built for (3.x, per its own install manifest) can't fill the
  gap either: its official Docker image's `entrypoint.sh` only wires up DB connectivity, it
  never calls any installer -- Joomla 3 has no CLI-driven unattended install at all, only a
  multi-step, session-stateful web wizard, which this project has no automation for and isn't
  building speculatively for one CVE.
  Rather than stop at "can't verify" or force a fragile Joomla-3-web-wizard scripting effort,
  shipped a genuinely new (and tested) path: `verify_joomla_legacy_module_sqli_cookie()` in
  `joomlaverify.py` skips the Joomla container entirely. It spins up only MySQL + a bare
  `php:8.3-cli` container (with `mysqli` installed at boot), copies the extension's real,
  UNMODIFIED source into it via `docker cp`, and runs it through a ~150-line stub environment
  (`_LEGACY_STUBS_PHP`) that does exactly one job: puts back the handful of `JFactory`/
  `JDatabaseDriver`/`JURI`/`JError`/`JLanguage*` method NAMES Joomla 4/5 deleted. Every stub
  either no-ops (UI/doc helpers) or passes the SQL straight to `mysqli_query()` with zero
  escaping or rewriting -- faithfully reproducing what the real Joomla 3 driver did, so the
  vulnerability executes exactly as shipped, not as reinterpreted. This is a genuinely different
  verification shape than every other `verify_joomla_*`/`verify_wordpress_*` function (which all
  hit a live, fully-rendered CMS over HTTP) -- it directly instantiates the extension's own
  helper class and times its constructor, the same time-based-blind-SQLi oracle
  `verify_generic_sqli_blind` already uses (median of 2 control runs as baseline,
  `verified=True` only if 2 INDEPENDENT repeats of the same payload both clear baseline + half
  the requested `SLEEP`), but with deeper closing-paren contexts
  (`_LEGACY_SQLI_CONTEXTS` includes `'))`/`')))` variants) than `genericverify.py`'s own list
  carries, because Joomla-legacy SQL typically nests the tainted value inside function calls
  (`UNHEX(SHA1('$val'))`, confirmed live against this exact CVE needing precisely 2 closing
  parens) rather than a bare `WHERE col='$val'`. (`genericverify.py`'s shared `_SQLI_CONTEXTS`
  was deliberately left untouched here -- the same nested-paren gap likely applies there too,
  but that constant is exercised by its own existing test suite against different assumptions,
  and fixing it blind without re-running that suite against something concrete would be the
  kind of unverified change this project doesn't ship.)
  Confirmed end-to-end for real, twice: first by hand, directly against the real downloaded
  `2.0.4j3` source (never committed -- policy), with timings that scale EXACTLY with the
  requested delay against a real, disposable MySQL (`SLEEP(0)` -> ~0.02s noise, `SLEEP(2)` ->
  ~2.03s twice independently, `SLEEP(5)` -> ~5.03s twice independently, against a ~0.02s
  benign-cookie baseline) -- proof it's the attacker-controlled cookie value actually being
  interpreted as SQL, not a fixed timeout artifact. Then shipped as a real, repeatable test,
  `test_joomlaverify_legacy_sqli_live_confirms_and_negative_control` in
  `tests/test_tools_and_config.py` (skipped without Docker): a SYNTHETIC module written to
  reproduce the identical vulnerability shape (never the real third-party zip, which the
  project doesn't distribute) gives `verified=True`, and the exact same module with the one
  real fix (`$db->Quote($this->callerIP)` instead of raw interpolation) gives `verified=False`
  -- not a verifier that always says yes.
  Deliberately NOT done in this session, flagged honestly rather than forced: (1) not wired
  into `cve_agent.py`'s automatic `investigate_cve` dispatch (which only knows
  `verify_joomla_account_takeover`/`verify_joomla_deserialization` for Joomla) -- this needed a
  second real CVE of this exact "legacy-extension-can't-even-boot" shape to generalize the
  dispatch hint correctly, and inventing that hint off a sample size of one would be guessing;
  (2) no automated Joomla 3 lab exists or was built for the "run the real extension inside an
  actual Joomla 3 frontend" version of this confirmation -- the web-installer-wizard automation
  that would require is real, scoped work of its own, not something to bolt on speculatively
  here.

- `drupalverify.py`'s FIRST real-CVE confirmation (it had a mature `verify_drupal_sqli` and
  Docker-lab bootstrap since before this session, but no CVE had ever been run through it end to
  end). Grounded in a real, current, open-source Drupal contrib module CVE:
  **CVE-2026-15081** / **SA-CONTRIB-2026-072** (contrib module `location_selector`, Views filter
  `LocationSelectorFilter::opEqual()`, affecting <1.3.0, fixed in 1.3.0, CWE-89). Unlike the two
  previous CVEs this project worked (Joomla/WordPress commercial extensions with no public
  mirror), this one is GPL and hosted on `git.drupalcode.org/project/location_selector` --
  cloned directly, confirmed the exact vulnerable/fixed boundary by diffing tag `8.x-1.2`
  (vulnerable) against `8.x-1.3` (fixed): `opEqual()` does `$value = key($values['selected'])` --
  the KEY of a nested JSON object the exposed filter's value decodes into, not a value -- then
  concatenates it RAW into `'JSON_CONTAINS_PATH(' . $field . ', \'one\', \'$."selected"."' .
  $value . '"\')'` via `addWhereExpression()`. The fix (`8.x-1.3`) switches to bound placeholders
  (`:mode`/`:path`).
  Two genuine, concrete gaps found by actually trying to run the existing `verify_drupal_sqli`
  against the real module (not guessed in advance):
  1. **The injection point is a JSON object KEY nested inside the parameter's value, not the
     raw value itself.** Drupal Views requires `$this->value` to be valid JSON
     (`json_decode()` gates the whole vulnerable branch) -- every existing SQLi technique in
     this project (`_SQLI_CONTEXTS`/`_LEGACY_SQLI_CONTEXTS`, and `verify_drupal_sqli`'s own
     local `contexts`) assumes the raw parameter value directly becomes the SQL fragment, so
     splicing a context+payload suffix onto it always breaks JSON syntax and the vulnerable
     code never even reaches the query builder. Fixed with a new, narrowly-scoped
     `json_key_envelope` parameter on `verify_drupal_sqli`: an opt-in template with a literal
     `{key}` placeholder: each candidate the 4 existing techniques already build gets
     substituted into the placeholder (double-quote-escaped for safety) before being sent, so
     the parameter stays valid JSON with the payload living in the nested key -- reusable for
     any future CVE with this same JSON-envelope shape, zero behavior change when unused.
  2. **The exploitable context needs a closing paren AFTER the injected SQL, not before it, and
     no closing comment.** Breaking out of the single-quoted JSON-path string lands INSIDE
     `JSON_CONTAINS_PATH(...)`'s still-open argument list, not at the top-level WHERE clause (the
     mirror image of the nested-paren shape `09e1daf` already handles) -- confirmed by reading
     the real MySQL 1064 error returned by a deliberately-too-simple payload. Worse: the
     vulnerable PHP template always appends a literal stray `"` right after the injection point,
     outside any string once broken out, so the obvious fix (`-- ` comment to eat the rest)
     backfires -- it also eats the derived-table's own closing paren that Views appends on the
     SAME line AFTER the WHERE clause, turning a working injection into an unrelated 1064. The
     winning real payload needs no comment at all: `x' OR SLEEP(5) OR '` breaks the string,
     injects the condition, and re-opens a one-character string that absorbs that stray `"` as
     literal content, letting the template's own trailing `'` and `)` resume their normal role.
     Added as one new entry to `verify_drupal_sqli`'s `timing_pairs` (the other 3 pre-existing
     entries are real attempts that simply can't reach this CVE's sink, not weakened).
  Also fixed a real, concrete scoring bug this CVE exposed in `verify_drupal_sqli`'s time-based
  blind step: it required 2 of N *different* `timing_pairs` entries to each independently show
  one delayed request, but for THIS CVE only 1 of the 4 entries is even syntactically capable of
  reaching the sink, so that threshold could never pass no matter how real the injection was.
  `genericverify.py`'s `verify_generic_sqli_blind` already solves this correctly (2 INDEPENDENT
  repeats of the SAME winning payload, both over threshold) -- ported that exact discipline into
  `verify_drupal_sqli`, which is a strictly stronger confirmation (two tries of one payload, not
  one try each of two), not a weaker one.
  A third real, concrete gap, scoped and fixed without generalizing beyond what this CVE
  actually needs: the advisory's own precondition ("a View that uses the affected filter AND is
  configured to accept user input") requires site configuration beyond what any previous
  `verify_drupal_*` needed -- a field of the vulnerable type, a node with it populated (with no
  matching row the JOIN has nothing to evaluate the WHERE expression against, and `SLEEP()`
  never runs), and a View exposing the filter as a GET parameter -- none of which `pm:enable`
  alone produces. Added `extra_setup_script` (optional PHP, run via `drush scr` right after the
  module is active): NOT a generic Drupal-site-building mechanism, exactly the verbatim script
  that creates the field (`FieldStorageConfig`/`FieldConfig`), the node (`Node::create()`), and
  the View (`View::create()` with the real schema a working Views config entity needs -- filter
  `plugin_id` matching what the module's own `hook_field_views_data_alter()` registers for its
  field type, same mechanism the real `location_selector_field_views_data_alter()` uses).
  Confirmed end-to-end for real, against the actual downloaded module (never committed):
  cloned `location_selector` at tag `8.x-1.2`, installed it into `drupalverify.py`'s real
  Drupal 10 + MySQL 5.7 lab, configured the field/node/View by hand first (via `drush scr`) to
  prove the precondition is buildable at all, then confirmed the real time-based blind SQLi by
  hand with `curl` (slow payload ~5.1s vs ~0.2s baseline, 3 independent repeats) before touching
  `verify_drupal_sqli` itself. After shipping the 3 fixes above, ran the ACTUAL extended
  `verify_drupal_sqli()` (not a hand-rolled script) against the same real module twice more:
  `verified=True` both times (`~5.0s` vs `~0.03s`, 2 independent repeats each run), and against
  the real FIXED `8.x-1.3` module as a negative control: `verified=False`, no delay at all --
  not a verifier that always says yes. Shipped as a real, repeatable test,
  `test_drupalverify_sqli_json_key_envelope_live_confirms_and_negative_control` in
  `tests/test_tools_and_config.py` (skipped without Docker): a SYNTHETIC module reproducing the
  identical vulnerability shape (never the real GPL module, which the project still doesn't
  distribute even though its license would allow it, for consistency with how the Joomla/
  WordPress tests already handle this) gives `verified=True`, and the same module with the real
  fix (bound `:mode`/`:path` placeholders) gives `verified=False`.
  Deliberately NOT done, flagged honestly rather than forced: not wired into `cve_agent.py`'s
  automatic `investigate_cve` dispatch (which has no hint for "needs `json_key_envelope`
  and/or `extra_setup_script`") -- same reasoning as the Joomla entry above, a second real CVE
  of this JSON-envelope-nested-key shape is needed before generalizing the dispatch hint
  correctly.

- Attempted second real-CVE generalization test for `verify_joomla_legacy_module_sqli_cookie()`
  (the reusable harness `ec3f98b` shipped and explicitly flagged as needing "a second real CVE
  of this exact legacy-extension-can't-even-boot shape" before trusting it as generic) --
  **could not be run, for an honest reason outside this project's control, not a code
  problem.** Target: **CVE-2025-26855** (`mod_articles_calendar` / "Articles Calendar",
  `joomcar.net`, 1.0.0-1.0.1.0007, CWE-89, CVSS 9.8), independently confirmed real via
  `cveawg.mitre.org`'s own CVE record. Unlike CVE-2025-40636 (the `mod_vvisit_counter` CVE this
  harness was built against), which had a real INCIBE advisory naming the exact cookie and
  helper method, this CVE's own CNA record (`providerMetadata.shortName: "Joomla"`) carries
  ONLY the boilerplate description ("A SQL injection ... allows attackers to execute arbitrary
  SQL commands") and a single reference -- the vendor homepage, nothing product-specific. No
  CWE location, no parameter, no file, no PoC anywhere.
  Tried every legitimate channel this project used successfully for the two prior Joomla/
  WordPress-class CVEs, and each came up empty:
  - `joomcar.net` itself: the live site no longer sells/serves the vulnerable 1.0.0-1.0.1.0007
    line at all. Its only "Articles Calendar" product today is **"Articles Calendar 2," built
    for Joomla 6** (a different major version than the CVE's affected range) -- and even that
    is gated behind a MetaMask/crypto-only payment flow (`payment_ajax=1&task=serveDownload`,
    confirmed by reading the page's own JS), not a free download. No changelog, no version
    history, no archived download link anywhere on the current site.
  - Internet Archive Wayback Machine: queried the CDX API for the whole `joomcar.net` domain
    (2000+ captures, 2011-2026) AND specifically for `/articles-calendar*` -- zero captures of
    any Articles Calendar product page EVER existed. The domain's actual archived history
    (2011-2020) is a completely unrelated Joomla K2/car-catalog demo site; the "Articles
    Calendar" storefront is a later, unarchived addition. `archive.ph` also has no snapshot.
  - Joomla Extensions Directory (JED): a real listing exists
    (`extensions.joomla.org/extension/calendars-a-events/time/articles-calendar`, found via a
    third-party aggregator, CommonNinja, that still links to it) but it is **unpublished**,
    marked `PE1` ("Under Investigation" -- "The JED team has received one or more user
    reports," can stay in this state indefinitely per JED's own knowledgebase) -- no vendor
    link, no download link, no description are shown on the live page. Searching JED's public
    Vulnerable/Resolved lists (both the browse pages and the title-filter query param) for
    "Articles Calendar" or "joomcar" returned nothing, consistent with PE1 (investigation) being
    a separate, earlier stage than the public VEL listing (UR3).
  - GitHub: no source mirror found anywhere. The one GitHub artifact that exists,
    `GHSA-qg92-5gwc-2jxx`, is an auto-generated advisory that only restates the NVD record --
    zero additional technical content.
  - MITRE/NVD/GCVE/`cve.imfht.com`/`cvelogic.com`/`mysites.guru`/INCIBE's own early-warning
    mirror: all independently re-publish the SAME one-line boilerplate description and the
    SAME single vendor-homepage reference; none names a parameter, file, or line, and none
    links a PoC or vendor advisory. (Contrast with INCIBE's CVE-2025-40636 page, which named the
    exact cookie and helper method -- confirmed by direct comparison.)
  - The credited finders (Kamil Szczurowski, Robert Kruczek) are real Polish security
    researchers, but their public work in this period (a DEF CON 2026 talk on scanning Poland's
    public-facing web en masse) is consistent with a bulk/automated extension-scanning campaign
    feeding Joomla's VEL/CNA pipeline directly, not a per-target technical write-up -- which
    matches this CVE record's complete absence of disclosed detail.
  No source code, no PoC, no advisory, no archived snapshot: **step 1 of this investigation
  (get the real vulnerable source and read the actual injection point) could not be completed
  by any available legitimate channel**, so steps 2-6 (confirm the injection shape, decide
  whether to reuse `verify_joomla_legacy_module_sqli_cookie()` vs. build something new, attempt
  live dynamic verification) could not honestly be attempted either. Deliberately did NOT: (a)
  guess at the injection point and write a "plausible" synthetic module as if it were a
  confirmed reproduction of this CVE's real shape -- every prior synthetic-module test in this
  project (`09e1daf`, the two entries above) was built only AFTER reading real vulnerable code
  first, to reproduce a shape that was actually confirmed, not invented; doing that here would
  be exactly the kind of unverified claim this project's own standard forbids; (b) use a piracy/
  "nulled extension" mirror to obtain the zip even though some likely exist, since that's outside
  this project's authorized-research scope regardless of the CVE being real.
  Net honest result: `verify_joomla_legacy_module_sqli_cookie()`'s generalization to a second
  real CVE remains UNTESTED -- not because it failed, but because no second real CVE candidate
  of this shape with actual public technical detail and obtainable source has been found yet.
  The concrete, reusable lesson for whoever picks this up next: prefer CVEs with a real vendor/
  CERT advisory naming the injection point (like CVE-2025-40636's INCIBE page) or an open-source
  target (like CVE-2026-15081's GPL Drupal module) over a Joomla-VEL/bulk-scan-sourced CVE whose
  only reference is a bare vendor homepage -- the latter is a strong signal that no public
  technical detail or source will exist, no matter how real the CVE itself is.

- Investigated a real, current, non-CMS CVE to exercise `genericverify.py`'s own
  (un-CMS-specific) lab bootstrap for the first time against a real target: **CVE-2026-9469**
  (`yashpokharna2555/StudentManagementSystem`, GitHub, plain PHP, commit
  `cb2f558ddf8d19396de0f92abf2d224d46a0a203`), unauthenticated SQLi in `/success.php` via the
  `user` POST parameter, CWE-89, independently confirmed real via `cveawg.mitre.org`'s own CVE
  record. Cloned the real repo at the exact commit and read the real vulnerable code: `success.php`
  builds `"SELECT * FROM \`admin\` WHERE \`user\` = '" .$user. "' AND \`password\` = '" . $h_pass . "' "`
  from `trim($_POST['user'])` with zero escaping, then `$db->query($sql)` (`connection.php`:
  `mysqli_connect('localhost', 'root', '')` against database `studinfosystem`) -- confirmed
  exactly where the CVE record's `/success.php` + `User` parameter said, with a real seed dump
  (`studinfosystem (8).sql`) providing the `admin` table and a real admin account.
  Found and fixed two genuine, concrete gaps in `genericverify.py`, each reproduced live against
  the OLD code first (per this project's own standard) before fixing:
  1. `_STACK_SIGNALS`/`_detect_and_write_auto_dockerfile` checked `package.json` BEFORE
     `composer.json`/bare-PHP detection, with no check that it actually declared a runnable Node
     app. This real repo's `package.json` is the one bundled with the "SB Admin" Bootstrap
     template (gulp/sass/jquery front-end tooling only, no `main`, no `scripts` at all) -- the
     OLD code misdetected it as a Node stack (confirmed live: `_find_build_target` on the real
     repo returned `stack_detectado: "package.json"`, generating a Dockerfile whose
     `npm start || node index.js || ...` never reaches anything real), which would have left the
     actual PHP app -- and the real SQLi -- unreachable. Fixed with
     `_package_json_has_runnable_entry()`: a `package.json` only counts as a Node signal if it
     declares a `main` or a non-empty `scripts`; otherwise detection falls through to
     composer.json/bare-PHP as before (confirmed live, same repo, same function: now returns
     `stack_detectado: "*.php (sin composer.json)"`).
  2. `verify_generic_sqli_blind` only ever tried `"<val> AND <sleep>"`. That requires the
     ORIGINAL parameter value to already match a real row -- true for CMS-specific verifiers
     that already know a valid identity, false for a generic login form probed without known
     credentials (the most common real case). Confirmed live against the real admin table (6
     rows): 45/45 AND-based context/dialect/comment combinations gave exactly 0.0s, despite the
     injection being real and independently confirmable with `curl` using `OR`. Raw `"<val> OR
     <sleep>"` does fire without needing a matching row, but `SLEEP()` inside an `OR` is
     evaluated once per row SCANNED, not once per query (confirmed live: `OR SLEEP(4)` against
     the same 6-row table took ~24s, not ~4s) -- a delay that grows unboundedly with table size
     and risks exceeding the request timeout on a larger table. Fixed by adding `OR` as a second
     boolean combinator (`_SQLI_BOOLEAN_OPS`), wrapping its sleep expression in a non-correlated
     derived subquery (`(SELECT 1 FROM (SELECT SLEEP(n)) x)`, `_sqli_sleep_clause`) that MySQL
     materializes once per query instead of once per row -- confirmed live, same real table:
     `~4.01s`/`~4.01s` across 2 independent repeats. Ran the ACTUAL extended
     `verify_generic_sqli_blind()` (not a hand-rolled script) against the real app, with a
     purpose-built lab Dockerfile (PHP + a local MariaDB server in the SAME container, needed
     because `connection.php` hardcodes `'localhost'` -- a separate compose `db` service would
     never be reachable by the real, unmodified source; never committed): `verified=True`, winning
     payload `user="nope' OR (SELECT 1 FROM (SELECT SLEEP(4)) binoracle_sqli_sleep)-- -"`,
     `~4.0s` vs a `~0.07s` baseline, 2 independent repeats. Negative control: the same real app
     with `success.php`'s query switched to a bound `mysqli` prepared statement (`?`/
     `bind_param`) gave `verified=False` across 81 combinations tried -- not a verifier that
     always says yes.
  Shipped two repeatable tests in `tests/test_tools_and_config.py` (skip cleanly without
  Docker): `test_genericverify_package_json_without_main_or_scripts_is_not_a_node_signal` (+ a
  positive-control sibling for a `package.json` that DOES declare `scripts.start`), and
  `test_genericverify_sqli_blind_live_confirms_or_combinator_login_no_match_and_negative_control`
  -- a SYNTHETIC Flask + real MySQL (via `docker-compose.yml`, never the real third-party PHP
  source) fixture reproducing the identical login-form/no-matching-row shape, confirmed
  `verified=True` (OR-based payload) against the vulnerable version and `verified=False` against
  the same fixture with a parameterized query. Ran the full genericverify-related suite: 55/56
  passed (including both new tests); the 1 failure
  (`test_genericverify_xss_blocked_without_build_target`) is the same pre-existing, unrelated
  Playwright-missing-sandbox gap `09e1daf`/`1b59422` already documented, confirmed by reproducing
  it identically against the pre-fix code. `ruff` clean on both changed regions (pre-existing
  findings elsewhere in the test file, untouched, same as prior commits). `mypy` errors on
  `genericverify.py`: the exact same pre-existing 11, confirmed by diff, just shifted by line
  number.
  Honestly incomplete, flagged rather than forced: SQLite does NOT execute the non-correlated
  derived-subquery form the same way MySQL does -- confirmed separately, by hand, while
  designing the test fixture: SQLite's query planner folds
  `(SELECT 1 FROM (SELECT SLEEP(n)))` to a constant WITHOUT ever invoking the registered
  `SLEEP()` function at all (returns instantly, no delay), unlike MySQL/MariaDB which
  materializes it exactly once. This only risks a missed detection on SQLite targets using this
  specific OR-bounded shape, never a false positive (consistent with this function's own stated
  tolerance for imperfect per-engine generalization) -- not fixed further here, since it wasn't
  needed for the real CVE (MySQL/MariaDB) and over-generalizing a SQLite-specific workaround
  without a second real CVE needing it would be guessing. Also not done: not wired into
  `cve_agent.py`'s automatic dispatch beyond what already existed for generic SQLi (this CVE
  needed no new dispatch hint -- `sqli_param_hint="user"` plus the existing generic path was
  enough once the two gaps above were fixed).

- First **path-traversal** CVE worked in this repo (vs. the three SQLi CVEs above): **CVE-2026-
  65694**, unauthenticated arbitrary file read in **Microweber CMS** <=2.0.20,
  `ServeStaticFileContoller::serveFromUserfiles()`, CWE-22, CVSS v4.0 8.7. Independently
  confirmed real via `cveawg.mitre.org`'s own CVE record. Read the real researcher PR
  (`microweber/microweber#1181`, unmerged at investigation time) and diffed it against the real
  base commit (`51ac711`, cloned straight from GitHub): the vulnerable code is
  `$path = $request->path; $path = normalize_path(userfiles_path() . $path, false); return
  $this->sendResponse($path, $request);` -- `$request->path`, accessed as a PROPERTY (not
  called as `$request->path()`), resolves via Laravel's own
  `Illuminate\Http\Request::__get($key) { return Arr::get($this->all(), $key, fn () =>
  $this->route($key)); }`, i.e. it checks the request's QUERY/POST input FIRST and only falls
  back to the bound `{path}` route parameter -- so an unauthenticated `?path=../../../../etc/
  passwd` query string silently overrides the real `{path}` route segment on `GET /userfiles/
  {path}` (`routes/web.php`, middleware group `api.static` = only `SessionlessMiddleware` +
  `CheckResponseForModifications`, no auth, no install-check). `normalize_path()`
  (`App/functions/common.php`) only normalizes path SEPARATORS (`/`/`\` -> `DIRECTORY_SEPARATOR`,
  collapses doubles) -- it never strips `..`. The real fix (PR #1181): read the bound route
  segment via `$request->route('path')` instead, then confine with `realpath()` + a prefix check
  against `realpath(userfiles_path())`.
  Stood up the REAL, unmodified vulnerable app (not a reproduction): cloned the real repo at
  `51ac711`, built it with its OWN shipped `docker-compose.yml` (`thecodingmachine/php` +
  MariaDB) after one test-only infra fix -- the shipped compose pinned
  `thecodingmachine/php:8.1-v4-apache-node16`, but `composer.lock` requires PHP ~8.2/~8.3
  (confirmed live: the 8.1 image failed dependency resolution before even reaching the
  vulnerable code) -- bumped the tag to the `8.2` variant of the SAME image family (no
  application code touched). Installed Microweber for real via its own unattended CLI installer
  (`php artisan microweber:install --db-host=mariadb ...`), confirmed necessary live: an
  uninstalled Microweber returns HTTP 200 with its own "Installation" page on EVERY route,
  including the vulnerable one, so testing against a merely-booted-but-uninstalled instance is a
  guaranteed false negative, not evidence of anything. One more real, concrete gap found and
  fixed along the way (narrower than Microweber's own install flakiness, see below): the
  project's shipped `.htaccess` has an unconditional `RewriteCond %{REQUEST_URI} ^/userfiles/.*$
  [NC,OR] ... RewriteRule . - [PT,L]` that intercepts EVERY `/userfiles/*` request at the Apache
  layer before Laravel's router ever runs, for both existing files (served directly, fine) and
  non-existing ones (Apache's own `ErrorDocument 404`, confirmed live via the exact "Not Found"
  Apache signature vs. Laravel's own 404 view) -- an Apache-specific accidental partial
  mitigation that a standard nginx `try_files $uri $uri/ /index.php?$query_string;` deployment of
  this same app does NOT have. Disabled that one rewrite block (test-only, clearly commented,
  never touching the vulnerable PHP) to test the REAL vulnerable-code behavior rather than an
  Apache config artifact.
  Confirmed end-to-end for real, by hand with `curl` against the real installed app: `GET
  /userfiles/x?path=../../../../../../../../etc/passwd` returned the real `/etc/passwd` from
  inside the container; the same technique against `?path=../.env` returned the real `APP_KEY`/
  `DB_PASSWORD` (matching PR #1181's own stated impact); a planted random canary at
  `/tmp/binoracle_canary2.txt` came back verbatim too. Negative control: applied the REAL PR
  #1181 patch to the same running app (live-reloaded, no container rebuild needed since PHP is
  interpreted) -- both the `/etc/passwd` and canary reads then 404'd, while the legitimate
  `/userfiles/modules/microweber/default.css` asset kept working (no regression from the
  patch).
  While getting this real app running long enough to drive the ACTUAL `genericverify.py`
  function (not a hand-rolled script) against it, found and fixed one genuine, concrete,
  generalizable gap: `_bootstrap_generic_lab`/`verify_generic_path_traversal` had no way to run
  anything inside the container AFTER it starts responding to HTTP but BEFORE the attack begins
  -- exactly the Microweber "always-200-until-installed" problem above, which is not
  Microweber-specific (any framework needing a real install/migration step before its routes
  behave like production -- Drupal's Views needed the analogous thing, fixed in
  `drupalverify.py`'s `extra_setup_script` by `1b59422`). Added `setup_commands` (a list of real
  shell commands run via `docker exec` right after `discover_http()` succeeds, before any
  attack payload is sent; any failing command aborts with the real stdout/stderr instead of
  silently probing a half-booted target) to both `_bootstrap_generic_lab` and
  `verify_generic_path_traversal`. Shipped as a repeatable test (skips cleanly without Docker),
  `test_genericverify_path_traversal_live_needs_setup_commands_and_negative_control` in
  `tests/test_tools_and_config.py`, against a SYNTHETIC gated-install PHP app (never a real
  third-party source) reproducing the identical shape (always-200-until-a-flag-file-exists, plus
  the same `?path=` query-overrides-route-segment pattern as the real CVE): first proves the gap
  was real by running the vulnerable app WITHOUT `setup_commands` (`verified=False` despite being
  genuinely vulnerable -- the "not installed" page masks it), then WITH `setup_commands`
  (`verified=True`), then the patched app with the same `setup_commands` as a negative control
  (`verified=False`). A second unit test,
  `test_genericverify_path_traversal_setup_command_failure_aborts_honestly`, confirms a failing
  setup command aborts with the real error instead of continuing. Full genericverify-related
  suite: 69/70 passed (both new tests included); the 1 failure
  (`test_genericverify_xss_blocked_without_build_target`) is the same pre-existing, unrelated
  Playwright-missing-sandbox gap already documented in `09e1daf`/`1b59422`/the CVE-2026-9469
  entry above. `ruff` clean on both changed files.
  Honestly incomplete, flagged rather than forced: the actual LIVE, automated
  `verify_generic_path_traversal()` run against the real Microweber app (as opposed to the
  by-hand `curl` confirmation above, which IS complete and conclusive) could not be completed in
  this environment. Root cause is NOT a genericverify.py bug: Microweber's own `composer
  install` (run by its shipped `docker-compose.yml` on every fresh container) triggers, as a
  `post-autoload-dump` side effect of `artisan package:discover`, an EAGER database read
  (`ModuleRepository::getSystemLicenses()`, `SELECT * FROM system_licenses`) during its OWN
  first-boot bootstrap, BEFORE any migration has created that table -- this crashed the
  container with an uncaught `QueryException` on 2 of 3 attempts (including after adding a real
  `depends_on: condition: service_healthy` MariaDB healthcheck plus a 15s buffer, AND on a fully
  fresh `composer install` with no cached `vendor/`), but NOT on the very first attempt, which
  installed and booted cleanly end-to-end (that is the run the by-hand `curl` confirmation above
  used). This looks like non-determinism inside Microweber's own first-boot sequence (plausibly
  tied to Composer's own autoload/class-discovery ordering, which this investigation did not
  chase further) rather than a timing race this project's tooling can reliably paper over --
  documented here rather than forced, same standard as the Joomla-3-web-installer gap in
  `ec3f98b`. The new `setup_commands` mechanism and `verify_generic_path_traversal`'s own attack
  logic ARE confirmed correct and sufficient for this exact CVE shape (query-param-overrides-
  route-segment, `../` depth up to 12) via the synthetic live test above, which deterministically
  exercises the identical mechanism without Microweber's own flaky boot sequence in the way.
  Whoever revisits Microweber specifically should pin the install step with a retry loop around
  `docker compose up` (observed to self-resolve on retry) rather than trying to fix Microweber's
  package-discovery ordering from the outside.

- **PHP exposure/triage (`phpestate.py`), defensive-only, built the same night as the trigger
  that caused it**: on 2026-10-21, PHP's security team pre-announced two critical core RCEs
  nicknamed "php2shell" in the wild -- **CVE-2026-109618** / **CVE-2026-109619**, each
  pre-announced CVSS v4.0 9.2, security release scheduled 14:00 UTC the same day. Confirmed by
  hand, independently, before writing anything: php.net's own archive feed
  (`https://www.php.net/archive/2026.php`) carries exactly the advance notice described above and
  nothing more ("With the release, we will publish ... further details") -- no root cause, no
  affected-version range, no fixed version yet; `cveawg.mitre.org`'s own API returns
  `CVE_RECORD_DNE` for both IDs (RESERVED, no description). Several public GitHub repos already
  claim working PoCs for these IDs; independent review found strong evidence those are fake/bait
  (internal inconsistencies, claims contradicting the official unpublished status, anomalous
  star/fork ratios for day-old repos) -- not fetched, not trusted, not reproduced here. Building
  an exploit/trigger for a mechanism that is not published yet would be pure guessing dressed up
  as research -- exactly the overclaiming this project's whole standard (`versions.py`,
  `wpverify.py`: grounded over generated) forbids, so this ships as inventory/classification only,
  the same pre-CVE hygiene question `versions.py` already asks of other components: is this
  install old enough to be exposed to whatever the next security release turns out to fix.
  Three pieces: (1) `scan_php_local` finds real `php`/`phpX.Y` interpreters under given paths (or
  common install layouts), runs `php -v` for REAL (never inferred from package-manager metadata),
  and classifies the real version EOL/BEHIND/CURRENT/UNKNOWN; (2) `fingerprint_php_remote` is
  opt-in and gated behind an explicit `authorized=True` the caller must pass before a single byte
  is sent -- unset, it returns immediately without building or sending any request, mirroring
  this project's own Docker-gated dynamic verifiers (`wpverify.py` et al. never touch a target
  without an explicit, checked opt-in either); authorized, it sends exactly one passive GET and
  reads only standard response headers/cookies already sent to any visitor, never a crafted path
  or payload; (3) `classify_php_version` returns one of EOL/BEHIND/CURRENT/UNKNOWN, with UNKNOWN
  reserved for "no data available" so a branch this tool simply hasn't catalogued is never rounded
  up to CURRENT or down to EOL. Output is `Finding` (the static-inventory shape `versions.py`
  uses), not `WpVerifyResult` -- this module never runs or confirms an exploit end-to-end, so a
  `verified` flag would be a lie here.
  Verified live, the same day, by hand: `https://www.php.net/releases/index.php?json&version=
  <major.minor>` is real and reachable (confirmed with `curl`) -- for a supported branch (e.g.
  `8.2`) it returns that branch's real latest patch (`8.2.34` as of this writing) plus the full
  list of currently-supported branches (`8.2`-`8.5`); for an EOL branch (`7.4`, `8.1`, `8.0`, all
  confirmed live) the same query returns the SAME supported-branch list with that branch absent
  from it -- exactly the EOL signal `classify_php_version` needs, with no extra endpoint or
  guesswork. This is the live counterpart to the static fallback table (`_STATIC_LATEST`,
  confirmed by hand against `https://www.php.net/archive/2026.php`'s own release announcements,
  dated `2026-09-24`): same "umbral conservador" honesty as `versions.py` -- every finding built
  from the fallback says so, and says it can go stale.
  One genuine, concrete, honestly-documented environment gap found while testing, not papered
  over: the live feed fetch succeeds under this machine's Homebrew Python (`/opt/homebrew/bin/
  python3`, confirmed live with `curl` and with a bare `urllib` call) but fails with
  `SSLCertVerificationError: self signed certificate in certificate chain` under this repo's own
  tested interpreter (`/Library/Frameworks/Python.framework/Versions/3.10`, the one `pytest` runs
  under in this sandboxed dev container) -- reproduced with a bare `urllib.request.urlopen` call
  with no `phpestate.py` code involved at all, so it is a property of this dev sandbox's
  TLS-intercepting proxy and that specific interpreter's trust store, not a bug in this module.
  `fetch_live_release_data` already catches this (and any other network failure) generically and
  returns `None`, which is exactly the fallback-to-static-table path the tests exercise -- so the
  behavior this gap exposes IS the intended honest degradation, not a defect; flagged here only so
  whoever next runs this tool's one opportunistic live test somewhere else is not confused if it
  behaves differently depending on which `python3` binary matters.
  Shipped as its own module and test file: `tests/test_phpestate.py`, 17 tests, 16 passed + 1
  skipped (the one opportunistic real-network test against php.net itself, which skips cleanly --
  not fails -- when the feed is unreachable, same pattern as this repo's Docker-availability
  skips) -- version parsing against a real (fake, but genuinely executed) `php -v` script,
  EOL/BEHIND/CURRENT/UNKNOWN classification against both a faked live feed and the static
  fallback, the bounded-depth directory walk, vendor/lookalike-name filtering, and -- the hard
  requirement from this task -- a test proving `fingerprint_php_remote` calls `urllib.request.
  urlopen` ZERO times when `authorized` is unset, plus a second test confirming it sends EXACTLY
  one request to the EXACT URL given once authorized. `ruff` clean on both the module and the
  test file. Wired into the CLI (`binoracle phpestate [paths...] [--url URL] [--authorized]
  [--json PATH] [--output PATH]`), since this operates on filesystem paths/URLs rather than a
  compiled binary, the same shape as `fetch`'s standalone command, not something that fits inside
  `audit.py`'s per-binary ToolRegistry pipeline alongside `versions.py`.
  Honestly incomplete, flagged rather than forced: (1) the live feed gives the latest patch for a
  specific branch but no historical CVE-count/severity data -- classification here is purely
  version-skew (EOL/BEHIND/CURRENT), never a CVE claim, by design; (2) remote fingerprinting is
  passive-header-only, confirmed against a REAL target (php.net's own homepage, fetched live,
  authorized as the tool's own informational source rather than a system under test) to return
  the honest "no PHP version visible" result, since php.net itself serves through BunnyCDN with
  no `X-Powered-By`/`Server: PHP` token -- this is the real-world shape of the exact limitation
  documented in the module's own rationale text (`expose_php=Off`, CDN/WAF stripping headers),
  not a hypothetical; (3) nothing here references CVE-2026-109618/109619 by mechanism, and nothing
  ever will from this module alone -- if/when php.net publishes real technical detail this
  afternoon, a FOLLOW-UP CVE-specific verifier (grounded in the real advisory, not this guess-free
  placeholder) would be the next real step, not a change to this file.

## Explicitly out of scope

- Weaponization against real third-party systems. Everything stays for authorized software,
  CTF challenges, lab malware, and authorized engagements.
- Turn-key malware payload kits.
