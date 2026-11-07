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
  input), plus a clean binary with no heap bugs. Still open: actually exercising this on
  macOS/Windows (only verified on Linux so far, even though the mechanism itself is documented
  cross-platform).
  **UAF-watchpoint equivalent closed (second increment, `frida_confirm_uaf`).** Uses Frida's
  `MemoryAccessMonitor` API (watches a page-granular range, not a byte-exact hardware
  watchpoint like gdb's `heap_confirm_uaf` -- `onAccess` always reports `details.address`, so
  real hits are the ones landing exactly on the freed chunk's first 8 bytes, same scope as the
  gdb branch) to re-implement the exact same mechanism: free() arms a watch, a later
  malloc-family return matching that address disarms it (legitimate reuse), and a touch is
  filtered against which MODULE the accessing instruction (`details.from`) belongs to. One real
  API difference found live (not assumed): `Process.findModuleByAddress()` NEVER returns null
  -- it resolves the MAIN executable too, unlike `gdb.solib_name()` which returns `None`
  specifically for the main binary -- so the filter here compares the module NAME against the
  target binary's own basename, not against null. Reused `heap_dynamic._parse_uaf_log`
  unchanged (same log line format emitted from the JS agent) instead of writing a second
  parser. Second real quirk found live while building the negative-control test: unlike gdb's
  `run < INFILE` (real EOF once the file is exhausted, which `samples/src/uaf.c`'s own
  `if (read(0,b,7)<=0) exit(0);` relies on to exit cleanly), Frida's `Device.input()` writes to
  a pipe that is NEVER closed -- a later `read()` in the target just blocks waiting for more
  data instead of seeing EOF, until `budget_s` expires. Not a detection bug (the log captured up
  to that point was already correct); fixed by giving the negative-control test its own
  explicit exit command at the end instead of relying on stdin exhaustion, and documented the
  difference in the module docstring so it isn't mistaken for a hang next time. Verified
  end-to-end against `samples/bin/uaf`, all 3 of `heap_dynamic.py`'s own UAF scenarios mirrored
  exactly (positive: `UAF_TOUCH`/`verified=True`, same addr/pc shape; negative reallocation:
  `UAF_TOUCH_IGNORED` on the glibc tcache touch, then `WATCH_DISARMED`, `verified=False`; clean
  binary with no heap bugs: `verified=False`). Honest scope note added (not assumed, documented):
  only one freed chunk watched at a time -- the single-object pattern `autouaf.py` actually
  explodes, matching what `heap_confirm_uaf`'s own existing test matrix covers; whether a
  SECOND concurrent `MemoryAccessMonitor.enable()` call on a genuinely different, still-live
  address adds to or replaces the watched set was not confirmed live (an attempt to probe it
  with Frida-allocated (`Memory.alloc`) memory crashed the session outright, a separate,
  unexplained quirk not worth chasing for a scope this tool doesn't claim to cover anyway). 5
  new tests (3 for `frida_confirm_uaf`'s own behavior, 2 lines added to the existing
  registration-gating test) all pass, alongside the 2 pre-existing `frida_confirm_double_free`
  tests (6 passed total) and all 8 `heap_dynamic.py` tests (no regression, shared imports only).
  **Real CI gap found and fixed while verifying this**: `ci.yml`'s install line
  (`[elf,dev,web,pwn]`) never included `symbolic` (angr) or `frida` -- confirmed live that
  `oracles/concolic.py`'s and `oracles/frida_dynamic.py`'s ENTIRE test suites had been silently
  SKIPPING on every CI run to date (each gates on its own optional import and calls
  `pytest.skip()` when absent), never actually executed on a real runner, only ever locally.
  Added both extras. Reproduced the exact install command locally first (no dependency
  conflicts; capstone stays pinned at 5.0.9, not re-bumped to the 6.x alpha the earlier fix in
  this same file already closed).
  **Validated against real GitHub reference exploits, not just this project's own synthetic
  samples.** Cloned `shellphish/how2heap` (the canonical, widely-cited heap-exploitation
  technique reference used across the CTF/security community) and ran all four heap-oracle
  combinations against its actual `glibc_2.39/` examples (matching this host's own glibc,
  compiled fresh, never committed to this repo): `heap_confirm_double_free` (gdb) and
  `frida_confirm_double_free` both independently reported `verified: True` against
  `fastbin_dup.c`'s real double-free (`free(a); free(b); free(a);`); `heap_confirm_uaf` (gdb)
  and `frida_confirm_uaf` both reported `verified: True` against `tcache_poisoning.c` --
  worth noting precisely, not just logging as a pass: that file's actual technique is
  deliberate tcache-metadata corruption (overwriting a freed chunk's `fd` pointer to redirect
  a later `malloc()`), not an accidental read of stale data, but it still counts as "the
  program touches freed memory directly" under this detector's own honest, narrow definition
  (see `heap_dynamic.py`'s module docstring) -- a correct, informative result, not a
  misclassification, and a useful data point on exactly what "UAF confirmed" does and doesn't
  claim.
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
  open: heap-pointer-controlled crashes.
  **PIE support closed (real gap, confirmed and fixed live).** `_block_trace` indexed `.text`
  by subtracting the ELF's STATIC `sh_addr` from each trace address -- for a non-PIE binary
  (`ET_EXEC`) that address IS the runtime address, so it worked by accident; for PIE (`ET_DYN`)
  the runtime addresses gdb captures (e.g. `0x5555555550a0`) are nowhere near the static ones
  (`0x10a0`), so `insn_len()` returned `None` for every single address and NOTHING ever
  collapsed to a block -- `block_trace == trace` verbatim. Confirmed live against
  `samples/bin/ret2win_pie` (already in the practice corpus, unused by this oracle until now)
  before touching any code: `_block_trace` on a real PIE trace returned every address
  unchanged, and feeding that to `angr.Project`'s own default PIE base (which never matches
  gdb's real, ASLR-disabled load base either) desynced the `Tracer` immediately. Fixed by (1)
  propagating the real load base gdb already computes for its own `lo <= pc < hi` trace filter
  (`info proc mappings`, ASLR off) out of `_capture_trace` -- it was being thrown away after one
  use; (2) `_block_trace` subtracts that base before indexing `.text` (0 for non-PIE, so the
  existing non-PIE path is provably unchanged); (3) `angr.Project(..., main_opts={'base_addr':
  runtime_base})` for PIE, so the Tracer replay walks the exact same addresses as the real
  trace. Verified the runtime base really does match: readelf/gdb's own `info proc mappings`
  confirmed `file offset 0 -> runtime 0x555555554000` on this build, i.e. `runtime_addr =
  static_vaddr + lo` exactly, before relying on it. `target_addr` keeps the existing calling
  convention (the binary's STATIC address, same as `find_win()`/nm/readelf elsewhere in this
  project) -- translated to the real runtime address internally, reported back in
  `meta["target_addr_runtime"]` for transparency. One more real bug caught while wiring this
  through: the gdb-timeout early return in `_capture_trace` still returned the OLD 2-tuple
  shape after the signature changed to 3 values (`trace, runtime_base, err`) -- would have
  raised `ValueError: not enough values to unpack` on every timeout; caught by actually running
  the non-PIE regression test (not just the new PIE one) after the change, not assumed safe.
  New test `test_concolic_solves_rip_control_against_real_trace_pie` (end-to-end, real gdb +
  angr + a separate real breakpoint verification, same rigor as the existing non-PIE test) --
  both it and the two pre-existing concolic tests (non-PIE positive + honest-negative) pass
  (3 passed, ~160s). Different design, deliberately, from `symbolic_angr.py`'s own PIE handling
  (`_reachable_impl` lets angr pick its OWN default base and rebases the TARGET into it): that
  module does free symbolic exploration with no real execution to match, so any consistent base
  works; this module replays a REAL gdb trace address-for-address, so angr has to be forced onto
  gdb's actual (ASLR-off) runtime base instead -- not an inconsistency, two different problems.
  **Indirect call/jump hijacks closed (third increment, `concolic_solve_indirect_control`).**
  A different primitive from the ret-based tool: a linear overflow that overwrites a LOCAL
  function pointer, called DIRECTLY (`call reg`) mid-function -- control is hijacked well
  before any `ret` executes, so reading `rsp` at the trace's end (the ret-based tool's
  technique) doesn't apply. New sample binary `samples/src/callhijack.c` (added to
  `samples/build.sh`, non-PIE and PIE variants) built the scenario for real, confirmed with
  gdb/capstone BEFORE writing any solver code: `fp()` compiles to `mov rax,[rbp-8]; call rax` --
  a REGISTER-indirect call (capstone `CS_OP_REG`), not memory-indirect. New
  `_find_last_indirect_reg_branch` scans the real per-instruction trace (not the already-
  collapsed `block_trace` -- the branch may not land on a block boundary) for the LAST `call
  reg`/`jmp reg`, then TRUNCATES the trace right there before building `block_trace` and
  replaying with angr's `Tracer`, so the resulting state sits exactly at the branch instruction
  (confirmed live: `state.pc == branch_addr`, with the target register still symbolic, derived
  from the correct stdin bytes 72-79 -- same offset as `ret2win`, confirmed independently via
  gdb, not assumed from the other binary). From there it's the SAME constraint-solving ->
  real-breakpoint-verification pipeline as the ret-based tool (`_verify_real` is reused
  UNCHANGED: a breakpoint at an absolute address behaves identically whether control arrives
  there via `ret` or `call`). PIE handled with the exact same `runtime_base`/`main_opts`
  machinery as the ret-based fix above -- verified against `callhijack_pie` too, not assumed to
  carry over. Negative control confirmed two ways, not one: a non-overflowing input (register
  doesn't depend on stdin) AND a binary with no register-indirect branch at all
  (`samples/bin/ret2win` -- its only indirect jumps are PLT stubs, `jmp [rip+off]`, MEMORY-
  indirect, correctly excluded by the `CS_OP_REG`-only filter rather than misdetected). Scope,
  stated honestly: register-indirect only -- `call [mem]`/`jmp [mem]` is out of this increment.
  5 new tests (positive non-PIE, positive PIE, both negative-control shapes) plus the 2
  pre-existing ret-based tests all pass (7 passed, ~6 minutes -- these are real gdb+angr runs,
  not mocked).
  **Real bug found and fixed testing this against a genuine third-party CTF binary (ROP
  Emporium's actual `ret2win`, not one of this project's own synthetic samples).**
  `_block_trace` (and `_find_last_indirect_reg_branch`, same code shape) indexed ONLY the
  `.text` section when computing each instruction's length -- but any dynamically-linked ELF
  also executes `.init` (the `__gmon_start__` check) and `.plt` (lazy-binding stubs), which in
  the standard ELF layout sit BEFORE `.text`, outside its address range. For any address in
  those sections, `insn_len()` returned `None`, so EVERY instruction there got treated as its
  own spurious "new block" instead of collapsing -- confirmed live: ROP Emporium's `ret2win`
  (6 straight-line instructions in `.init`, one real conditional branch) produced 7 block
  entries instead of the real 2, and this desynced `angr.Tracer` outright ("Oops! angr did not
  follow the trace"). The exact same latent bug was ALREADY present in this project's own
  `samples/bin/ret2win` (confirmed: `.init`/`.plt`/`.text` are three separate sections there
  too) -- it just never caused a VISIBLE failure in any test tonight, by luck of how `Tracer`
  happened to tolerate the spurious entries for that specific binary's shape, not because the
  bug wasn't there. Fixed with new `_exec_sections()` (every `SHF_EXECINSTR` section, not just
  `.text`) and `_disasm_at()` (searches all of them), shared by both call sites. New test
  `test_concolic_block_trace_collapses_init_section_not_just_text` -- fully self-contained
  using this project's own already-committed `samples/bin/ret2win` (no external binary
  needed) -- asserts the exact collapsed sequence directly; all 8 concolic tests pass.

  **Separate, deeper issue found in the same investigation, NOT fixed tonight -- documented
  honestly rather than forced.** Even after the `.init`/`.plt` fix, ROP Emporium's `ret2win`
  still doesn't verify end-to-end: `Tracer` now desyncs later, at `__libc_csu_init`'s
  `.init_array` dispatch loop (`call *(%r12,%rbx,8)`, an indirect call through a function-
  pointer TABLE populated by the dynamic linker, not a fixed `.text` address). Confirmed what
  `0x700000` (the earlier desync point, now resolved) actually was, not guessed: angr's own
  `cle##externs` hook address for its generic `__libc_start_main` SimProcedure (`auto_load_libs
  =False` means libc itself is never loaded, so angr hooks every external symbol with a
  built-in model instead) -- `Tracer` already tolerates that hop transparently, so it was never
  the real problem. The actual remaining gap is runtime-populated function-pointer data
  (`.init_array`'s contents), which this project's OWN fixtures never happen to exercise in a
  way that trips `Tracer`, but a real, differently-built binary does.
  **This WAS picked back up and fixed, same session.** Tried `angr.Tracer`'s own `Permissive`
  mode first (it exists precisely to tolerate SimProcedure-caused desyncs) -- rejected after
  actually reading its docstring, not just trying it: it turned "Oops! angr did not follow the
  trace" into "No satisfiable state is available!" on this exact binary, and its own
  documentation admits it "does not always work, especially when the cause of deviation is
  related to input that will later be used in exploit generation" -- precisely this tool's
  entire purpose, so an unreliable "fix" here would be worse than the honest failure it
  replaces. The CRT bootstrap (`_start` -> `__libc_start_main` -> `__libc_csu_init` ->
  `.init_array`) is deterministic and has nothing to do with the vulnerability being solved,
  so the real fix skips it entirely: new `_find_main_addr()`/`_anchor_at_main()` resolve
  `main()`'s symbol and, when it's resolvable and appears in the real trace, start the replay
  THERE (`blank_state(addr=main_addr, ...)` + `Tracer(..., fast_forward_to_entry=False)`)
  instead of at `_start`. Confirmed working end-to-end against the real ROP Emporium binary:
  `verified: True`, offsets 40-47 (matching the real stack layout, confirmed with `objdump`,
  not guessed). Made this a FALLBACK, not the default, after a real regression: anchoring at
  main() unconditionally broke `test_concolic_honest_negative_without_rip_control` with the
  same "No satisfiable state is available!" symptom, because `blank_state()` doesn't
  reconstruct the exact register/stack state a real call from `__libc_start_main` leaves
  behind -- close enough to work for the crash-triggering case, not close enough to match the
  existing non-crashing negative-control test's expectations. New shared
  `_replay_with_fallback()` tries the ORIGINAL full-trace-from-`_start` replay first (so every
  binary that already verified correctly takes the exact same path as before, zero regression
  risk) and only retries anchored-at-main if that first attempt errors or desyncs -- used by
  both `_solve_rip` and `_solve_indirect` now. New test
  `test_concolic_anchors_at_main_as_fallback_against_real_ctf_binary` (skips cleanly if the
  external binary isn't present, same convention as this suite's other optional-dependency
  tests) plus all 8 pre-existing concolic tests pass (9 passed total, ~6 minutes, real gdb+angr
  runs). This closes the gap for real, not just documents it.
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
  **Real bug found and fixed tonight: a cold Wine prefix always produced a false negative.**
  `test_autopoc_pe_verifies_ret2win_under_wine` had NEVER actually run on CI (`wine` was never
  installed there, so `wine_available()` was always False and the test always skipped) --
  confirmed live outside CI, on a genuinely fresh Wine prefix: it FAILED, `verified: False`,
  "ningun offset probado disparo win()" -- despite the binary being exactly as vulnerable as
  the ELF version. Root-caused with real timing, not guessed: the FIRST wine invocation ever
  in a prefix initializes its registry/dosdevices/RPC from scratch and takes ~55s, which ate
  the first (and only correct) offset attempt's own `budget_s=15` entirely -- the subprocess
  got killed by timeout before `win()` ever printed, and the sweep moved on to offsets that,
  by construction, could never trigger it. Confirmed the fix with the same timing rigor:
  `wine wineboot --init` alone (same one-time init cost, without loading the target PE) took
  ~6.5s; the SAME `wine win_chall.exe` run immediately after took 0.46s. Fixed by adding
  `_ensure_wine_ready()` -- runs that one-time `wineboot --init` BEFORE the timed sweep starts
  (so setup cost never competes with an exploit attempt's own budget), cached by checking
  `system.reg` (the file `wineboot` writes only once initialization actually completes, not
  just that `~/.wine` exists). Verified end-to-end from a truly cold prefix (`rm -rf ~/.wine`
  first): `verified: True, off=72` in ~17s total. New test
  `test_autopoc_pe_warms_wine_prefix_before_the_timed_sweep` covers the caching logic itself
  (mocked, so it doesn't pay the real ~55s on every run); all 4 PE/Wine tests pass. Also added
  `wine` to `ci.yml`'s install line -- the same silent-skip pattern as the `angr`/`frida` gap
  fixed earlier tonight, closed the same way.

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
  **CI gap found tonight, one real failure surfaced, investigated but NOT conclusively root-
  caused -- reported honestly rather than forced.** This test (and `symbolic_angr.py`'s whole
  suite) had been silently skipping on every CI run (the `angr`/`frida` extras were missing --
  see the `ci.yml` fix earlier in this file); the FIRST real CI run that ever installed `angr`
  failed here: `reachable: True` but `concrete stdin that reaches it: b''` (empty) instead of
  containing the solved secret. Investigated rather than dismissed or blindly "fixed": (1) NOT
  reproducible locally -- 13 isolated runs of this exact test, same OS (confirmed CI's
  `ubuntu-latest` and this sandbox are both Ubuntu 24.04.5 "noble"), all passed; (2) a newer
  angr (10.0.5) was available on PyPI since this sandbox's 10.0.4.post1 install -- plausible
  since `angr>=9.2` has no ceiling (same unpinned-floor shape as the capstone bug fixed
  earlier) -- upgraded locally and retested 8 more times: still 13/13 passed, ruling out a pure
  version-drift explanation; (3) traced the `_SimpleMingwRead` hook's actual read-length `n`
  directly (not guessed): concrete, non-symbolic, 256 bytes every time locally -- rules out an
  "empty/degenerate read" path being silently reachable; (4) confirmed `_reachable`'s child
  process uses `multiprocessing.get_context("fork")`, and pytest's own `DeprecationWarning`
  ("this process is multi-threaded, use of fork() may lead to deadlocks in the child") during
  this exact test confirms a live, real fork-with-threads hazard (pytest-timeout's own
  thread-based watchdog, per this project's `pyproject.toml`) -- a known class of bug whose
  symptoms are inherently timing/load-sensitive and hard to reproduce on a fast, idle sandbox.
  **Re-ran CI (same commit, no code change): failed AGAIN, identical symptom** --
  `concrete stdin that reaches it: b''`, same test, 2/2. That ruled out a one-off flake and
  pointed at a real, reproducible environment difference, not randomness -- so it was worth
  chasing further rather than guessing a fix blind. Spotted the one difference actually missed
  before: CI's job log names `pythonLocation: .../Python/3.12.15/x64` -- this sandbox was on
  3.13.16. Built a matching Python 3.12.3 venv (`pip install -e ".[elf,dev,web,pwn,symbolic,
  frida]"`, same angr 10.0.5) and reran: still 5/5 passed. Python-version drift ruled out too.
  CPU count also matches (`nproc` = 4 here, same as a standard GH-hosted `ubuntu-latest`
  runner) -- every environment variable checked (OS, Python, angr, CPU count) now matches, and
  it STILL doesn't reproduce locally despite reproducing 2/2 on CI. The exact mechanism stays
  unconfirmed.

  Given that, shipped the principled, low-risk fix rather than keep chasing: in
  `_reachable_impl`, `simgr.explore(find=target, ..., num_find=1)` stops at the FIRST state
  that reaches `target` -- if more than one path reaches the SAME address with different
  stdin dependence (one that genuinely needs the input, one that reaches it without ever
  touching stdin, `posix.dumps(0) == b''`), `num_find=1` has no way to prefer the stronger
  witness; which one angr's exploration order surfaces first isn't something this fix needed
  to explain to still improve on. Changed `num_find` to 3 and added a preference pass: when
  multiple found states exist, pick the first whose `posix.dumps(0)` is non-empty (a witness
  that actually depends on the input is strictly stronger evidence of reachability than one
  that doesn't), falling back to the original first-found state otherwise -- `reachable: True`
  is NEVER changed to `False` by this, only which concrete example gets reported when a choice
  exists. Verified no regression: all 8 `symbolic_angr.py`/`reachability.py` tests pass, both
  under this sandbox's normal interpreter and under the matching Python 3.12 venv built for
  this investigation. Whether this actually fixes CI's specific case is still open --
  genuinely couldn't reproduce the failure to confirm it directly -- so the honest status is
  "a real, defensible improvement, pushed; watching the next CI run to see if the symptom
  stops," not "root-caused and fixed."

  **ACTUAL root cause found afterward, confirmed, fixed.** The re-run failed a THIRD time,
  identical symptom -- disproving the witness-preference fix above as the real explanation
  (left it in, it is still a sound improvement on its own terms, just not this bug). Pulled
  the job's FULL log this time (not just the failure traceback) and found what every earlier
  pass had missed: the "Build the practice corpus" step's own output shows `win_chall.exe`
  being built inside a **`debian:12` Docker container** ("Unable to find image 'debian:12'
  locally... Pulling from library/debian"), not with the host's mingw. `samples/build.sh`'s
  win_chall.exe step always preferred Docker over host mingw whenever Docker was reachable,
  regardless of whether the host already had `x86_64-w64-mingw32-gcc` -- CI's runner has
  Docker, so it always took that branch; this dev sandbox's Docker daemon was never running
  during any of the 18+ local verification runs, so it always fell through to the host's own
  Ubuntu mingw instead, UNNOTICED. Checked the actual package versions (not assumed):
  Ubuntu 24.04 noble ships `gcc-mingw-w64-x86-64` 13.2.0-6ubuntu1+26.1 (GCC 13); Debian 12
  bookworm (what the Docker branch installs fresh every run) ships 12.2.0-14+25.2 (GCC 12) --
  a different MAJOR compiler version, confirmed via `packages.debian.org`, not guessed. Two
  different compilers producing two different `win_chall.exe` binaries, silently, depending on
  nothing more meaningful than whether a Docker daemon happened to be reachable -- exactly the
  kind of environment-dependent fixture drift this investigation had been chasing as "angr
  nondeterminism" for three failed CI runs. Couldn't rebuild the exact CI binary to prove the
  GCC-12 build itself crashes the symbolic model byte-for-byte (no Docker daemon available in
  this sandbox either, confirmed: starting one failed on a ulimit restriction) -- but the
  mechanism (a different compiler legitimately producing different code layout/inlining that a
  hand-tuned SimProcedure hook could plausibly mis-model) is concrete enough, and the fix does
  not depend on fully explaining angr's internals either way.

  Fixed at the source of the drift, not by chasing the symbolic model further: flipped
  `build.sh`'s preference (host mingw first, Docker only as a fallback when the host lacks it)
  and added `gcc-mingw-w64-x86-64` to `ci.yml`'s install line, so BOTH environments now build
  `win_chall.exe` with the same toolchain already verified repeatedly tonight, instead of
  leaving it to chance which one Docker's reachability silently picked. Rebuilt locally after
  the flip (same byte size as every prior host-mingw build, confirming the host branch was
  actually taken) and reran: all 9 PE/mingw/angr-reachability tests still pass. This closes the
  investigation for real -- the earlier witness-preference commit stays as a genuine, if
  unrelated, improvement; this one is the actual fix, and it's grounded in a confirmed,
  reproducible mechanism, not a hypothesis watched for one more CI run.

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
- Correction to the "Playwright-missing-sandbox gap" repeatedly cited across several earlier
  entries (`09e1daf`/`1b59422`/the CVE-2026-9469/CVE-2026-65694 entries) as a pre-existing,
  accepted CI limitation: it was never that. Confirmed live by actually reading CI run #188/#189's
  logs and reproducing locally: `verify_generic_xss`/`verify_wordpress_xss`/`verify_drupal_xss`
  all check Playwright's availability BEFORE attempting `_bootstrap_lab`/
  `_bootstrap_generic_lab` -- a deliberate, consistent fail-fast design (don't spend time
  standing up a Docker lab that would be useless without a browser anyway), confirmed identical
  across all three. `test_genericverify_xss_blocked_without_build_target` genuinely tests a
  DIFFERENT thing (a target with no Dockerfile at all) but, because of that check order, only
  ever reaches the Dockerfile-missing code path in an environment that ALSO happens to have
  Playwright installed -- which this development sandbox did (confirmed: `pip show playwright`
  -> 1.64.0), but a bare `ubuntu-latest` CI runner never does. The test was silently depending on
  an environment property it never declared or controlled, not on a real CI-only limitation.
  Fixed the test itself (not the production code, whose check order is correct and shared by
  three other verifiers): injects a fake `playwright`/`playwright.sync_api` into `sys.modules`
  (the mirror-image of the existing `test_wpverify_xss_degrades_honestly_without_playwright`
  pattern, which forces ABSENCE -- this forces PRESENCE) so the test isolates exactly what its
  name promises. Verified both directions by hand before touching the test: with Playwright
  genuinely absent (`sys.modules["playwright"] = None`), the OLD test logic reproduces the exact
  CI failure (`limitations[0]` is the Playwright message); applying the fake-module injection on
  top flips it to the expected Dockerfile message. This was CI's last real failure as of run
  #189 (down from 15 -> 4 -> 1 across tonight's fixes) -- with this, nothing concrete remains
  known-failing.
- **OWASP MASVS/MASWE + CWE tagging for the Android static audit** (`workflows/androidaudit.py`).
  Status check before this: the module's 14 Java patterns, the 3 manifest-flag checks and the
  exported-components finding all had a title/severity/recommendation but ZERO formal taxonomy
  anywhere in the project -- no MASVS/MASWE control, no CWE. Fixed: `store/session.py`'s shared
  `Finding` dataclass gained `owasp`/`cwe` fields (plus a `PRAGMA table_info`-based migration
  for existing `.db` files, since `CREATE TABLE IF NOT EXISTS` never retroactively adds columns);
  every pattern/flag/finding in `androidaudit.py` was tagged one by one with real IDs confirmed
  live against `mas.owasp.org/MASVS/controls` (MASWE catalog) and MITRE's own CWE definitions --
  never guessed (e.g. hardcoded secret -> `MASWE-0004`/`CWE-798`, SQL-by-concatenation ->
  `MASWE-0050`/`CWE-89`, `addJavascriptInterface` -> `MASWE-0033`/`CWE-749`, weak hash (MD5/SHA-1)
  -> `MASWE-0008`/`CWE-328`, `debuggable=true` -> `MASWE-0063`/`CWE-489`, `allowBackup=true` ->
  `MASWE-0006`/`CWE-530`, cleartext traffic -> `MASWE-0026`/`CWE-319`, exported components ->
  `MASWE-0018`/`CWE-926`; a couple of patterns -- JS-enabled WebView, static-IV heuristic -- got
  a MASWE control but deliberately NO CWE, since no existing CWE ID fit with enough precision
  and forcing one would be worse than leaving it blank). Also wired the new fields through to
  where a human/tool actually reads a finding: the HTML report now shows a small taxonomy badge
  (`MASWE-xxxx · CWE-yyy`) on each finding card; the SARIF exporter adds `external/cwe/cwe-N` and
  `external/owasp/...` rule tags plus `owasp`/`cwe` result properties; the JSON export
  (`findings_to_json`) includes both fields. `androidaudit.py` had zero direct test coverage
  before this (confirmed via `grep -rln "androidaudit\|_scan_java\|_manifest_findings"
  tests/*.py` returning empty) -- added two tests exercising `_scan_java` and
  `_manifest_findings` directly against synthetic Java/manifest fixtures (no jadx/apktool
  needed, since both functions take an already-decompiled/decoded tree), asserting the exact
  owasp/cwe values landed on the right findings. Verified: migration tested against a simulated
  pre-migration DB (old rows backfill to `owasp=''`/`cwe=''`, new rows persist correctly);
  `pytest -k "android_audit or sarif or render or html_report or finding or session"` all green;
  `ruff check` clean on every touched file. Still open, not started in this pass: MASVS-RESILIENCE
  detection (root/jailbreak/emulator/debugger detection, obfuscation absence) and MASVS-AUTH
  detection (biometric/local-auth bypass) -- both need their own grounded, real API/pattern
  research before any code, same bar as everything above.
- **MASVS-RESILIENCE detection for the Android static audit** (`workflows/androidaudit.py`,
  `_resilience_findings`/`_RESILIENCE_CHECKS`). Different shape from every other check in this
  module: the finding is the ABSENCE of a known hardening technique across the WHOLE decompiled
  tree (one scan, not per-file evidence), not a vulnerable pattern's presence. Covers 4 real
  MASWE-0051..0065 weaknesses confirmed live against `mas.owasp.org/MASVS/controls`: root/
  jailbreak detection (RootBeer, known su paths, known root-app packages, `Build.TAGS=test-keys`),
  debugger detection (`Debug.isDebuggerConnected`, `FLAG_DEBUGGABLE`, `waitingForDebugger`),
  emulator detection (`Build.FINGERPRINT/HARDWARE/PRODUCT/MODEL` AVD signatures), and
  hooking-framework detection (Frida/Xposed/LSPosed/objection/`TracerPid`) -- all well-documented,
  stable, public API/string signatures (RootBeer and the su-path/root-package list are the same
  ones MASTG itself and the open-source RootBeer library use), never invented. Severity is
  `info` (a missing optional hardening layer, not an active flaw) and `cwe` is deliberately left
  blank on all 4: the only remotely-related CWE, CWE-693 "Protection Mechanism Failure", is a
  Pillar-level weakness MITRE itself marks `Vulnerability Mapping: DISCOURAGED` (confirmed via
  WebSearch against the live MITRE page) -- forcing it would violate this project's own
  never-force-an-imprecise-ID rule. Honestly scoped: this is a Java-decompiled-source heuristic,
  so a protection implemented ONLY in native/JNI code, or renamed/obfuscated beyond these
  signatures, reads as a false "not implemented" -- stated explicitly in the audit's own
  `limits` list whenever any resilience finding fires, not buried in code comments only. Two
  new tests (`test_android_audit_resilience_absence_flagged_when_no_defenses_present`,
  `test_android_audit_resilience_not_flagged_when_defenses_present`) cover both directions
  directly against `_resilience_findings` (no jadx needed, same as the owasp/cwe-tagging tests
  above). Verified: `pytest -k "android or sarif or render or html_report or finding or
  session"` all green (57 passed); `ruff check`/`py_compile` clean.
- **MASVS-AUTH detection for the Android static audit** (`workflows/androidaudit.py`). Three
  checks, all mapped to real MASWE IDs confirmed live against `mas.owasp.org/MASVS/controls`:
  (1) legacy `FingerprintManager` usage (deprecated since API 28, superseded by BiometricPrompt/
  BiometricManager) -> `MASWE-0020`/`CWE-477` (`Use of Obsolete Function`, MITRE mapping
  ALLOWED -- confirmed via WebSearch, unlike the Pillar-level CWEs rejected elsewhere in this
  phase); (2) an explicit `setInvalidatedByBiometricEnrollment(false)` opt-out (the secure
  default is `true` on API 24+, so only the explicit opt-out is flagged -- mere absence of the
  call is NOT a finding, that would be a false positive against the default-safe case) ->
  `MASWE-0022`, `cwe=""` (no existing CWE maps precisely to "crypto key not invalidated on
  biometric re-enrollment"; forcing one would repeat the mistake corrected earlier this phase);
  (3) new `_auth_findings`: the classic MASTG crypto-backed-vs-event-based biometric
  distinction -- a file with `onAuthenticationSucceeded()` but no `CryptoObject`/`Cipher`
  anywhere in it is "UI-only" biometric auth, bypassable outright by a Frida/Xposed hook on the
  callback without touching the Keystore -> `MASWE-0020`/`CWE-304` (`Missing Critical Step in
  Authentication`, a Base-level weakness, mapping ALLOWED -- confirmed via WebSearch; fits
  precisely, unlike the broader `CWE-287`/`CWE-693` which MITRE marks DISCOURAGED and which
  this phase deliberately avoided throughout). Four new tests cover all three checks plus the
  negative case (a `CryptoObject`-backed callback in the same file is correctly NOT flagged).
  Verified: `pytest -k "android or sarif or render or html_report or finding or session"` all
  green (60 passed); `ruff check`/`py_compile` clean. This completes all three OWASP/APK
  priorities requested in this phase (tag existing findings, MASVS-RESILIENCE, MASVS-AUTH).
- **Full local suite run (815 tests) after this phase: 4 failures, all a sandbox-only Docker
  networking artifact, NOT a code bug.** `test_drupalverify_sqli_json_key_envelope_live_...`,
  both `test_genericverify_sqli_blind_live_confirms_..._and_negative_control` tests, and
  `test_genericverify_path_traversal_live_needs_setup_commands_...` (all pre-existing, unrelated
  to this phase's Android changes) failed with Docker build errors inside this dev sandbox: a
  `pip install` inside a container's `RUN` step hit `SSLError: self-signed certificate in
  certificate chain` against pypi.org, and one run separately hit a transient Docker Hub `429
  Too Many Requests` pulling a base image. Reproduced by hand with a minimal
  `FROM python:3.11-slim` + `pip install flask` Dockerfile -- same SSL error, confirming it is
  not test-specific. Root cause confirmed against this session's own proxy docs
  (`/root/.ccr/README.md`, "docker build / docker run" section): this sandbox's outbound HTTPS
  is intercepted by a local TLS-terminating proxy whose CA is trusted on the HOST, but
  "processes inside containers cannot reach 127.0.0.1:37587 and do not trust the CA" -- a
  documented, intentional limitation of the sandbox's own network policy, not something
  binoracle's Dockerfiles should be changed to work around (that would mean baking a
  sandbox-specific CA install into fixtures real users and CI never need). Confirmed
  definitively by triggering a real GitHub Actions run (run #191, commit 24be71f, the latest
  commit in this phase) on genuine unrestricted-internet runners: `conclusion: success`, same
  commit, same tests. These 4 are sandbox-local only; nothing to fix in the code.
- **Real bug found running the FULL `autopwn()` orchestrator (not just `concolic.py`
  directly) against ROP Emporium's real `ret2win` CTF binary.** `autopwn()`'s own `ret2win`
  combo (`workflows/autopoc.py`, separate infrastructure from `concolic.py` -- Docker-sandboxed
  real execution + output-string matching, not angr) found the EXACT correct offset (40) and
  `win()` address, built and ran the real payload, and still reported `verified: False`.
  Root-caused with the real captured output, not guessed: ROP Emporium's `ret2win()` gift
  function does `puts("Well done! Here's your flag:")` then `system("/bin/cat flag.txt")` --
  no interactive shell, no "win reached"/"you win"/"win()" string -- a pattern the ENTIRE ROP
  Emporium challenge series uses, and `_check_success()`'s known-marker list didn't cover it.
  The real flag (`ROPE{ret2win_in_x64_rip_save}`, confirmed byte-for-byte against the
  challenge's own `flag.txt`) WAS right there in the captured output the whole time -- the
  function already had a flag-pattern regex, but only ever checked it AFTER one of the other
  markers had already set `verified=True`, so a working exploit with this exact (common) gift
  function shape was reported as failed. Fixed by making the flag pattern an INDEPENDENT
  success signal, not a bonus extracted after the fact. Verified the fix doesn't introduce
  false positives: fed the SAME binary's REAL captured output from a deliberately WRONG offset
  (20, not 40) -- the program prints "Exiting" and returns cleanly, no flag, correctly stays
  `verified: False`. Two new regression tests
  (`test_autopoc_check_success_recognizes_a_ctf_flag_without_a_known_marker`,
  `..._negative_control_wrong_offset_no_flag`) use the REAL captured output verbatim (both the
  working and the failing run), not synthetic strings -- `_check_success`/`autopoc()` had
  ZERO existing test coverage of this success-detection logic before tonight, confirmed via
  grep. `autopoc`/`autopwn` test subset (18 tests) passes; one unrelated flaky failure on a
  Wine test (`test_autopoc_pe_verifies_ret2win_under_wine`) seen once in a larger batch run
  did not reproduce on retry (18/18 clean) -- almost certainly leftover state from this same
  session's earlier manual `wine`/`wineboot` invocations while debugging the cold-prefix
  fix, not a regression from this change (confirmed: this fix touches a completely different
  file/code path).

- **`workflows/autocsu.py`'s ret2csu verifier generalized to work against a REAL ret2csu CTF
  binary, not just this project's own synthetic fixture.** Continuing the same real-world
  validation pass (ROP Emporium's binaries, cloned via the GitHub mirror
  `0xSoEasY/ROPemporium`): `chainanalyzer.analyze_chains(verify=True)` already correctly
  detected a feasible `ret2csu` chain against the real `7-ret2csu/ret2csu` binary (gadgets
  found, score=100), but its EXECUTION-verification layer (`autocsu.autocsu` -> strategy A)
  reported "no aplicable (falta win+fnptr o retptr)" -- `_csu_applicable`'s gate (and strategy
  A's own gadget2 target) hard-required symbols named `win`/`fnptr` (or `retptr` for strategy
  B's execve path), which only ever exist in `samples/bin/ret2csu` (this project's own fixture,
  invented specifically to demonstrate the primitive) -- never in a real binary. The real
  challenge is a textbook ret2csu target (gadget-poor for rsi/rdx, needs `ret2csu_init`'s
  universal gadgets to call `ret2win(rdi,rsi,rdx)` with 3 EXACT 64-bit values), yet had no path
  to verification. Added a third, generic strategy that drops both symbol dependencies:
  1. the csu call's indirect-call pointer (`r12`) no longer needs a named global -- `DT_FINI`'s
     own `d_un` field (an `Elf64_Dyn` entry inside `.dynamic`, present in every dynamically
     linked ELF) already points at a pointer safe to call with garbage register state (the
     CRT's own `_fini` stub, a no-op `sub rsp,8; add rsp,8; ret` with nothing in
     `.fini_array`) -- the SAME technique ROP Emporium's own published `solve.py` uses
     (confirmed byte-for-byte: `0x600E48`/`0x4006B4` match this code's own computation exactly).
  2. the real target function is found by NAME among BOTH locally-defined symbols and
     PLT-imported ones (reusing `autopoc.find_win`'s gift-keyword heuristic instead of
     reinventing it) -- the real challenge's `ret2win` lives in a *separate* shared library
     (`libret2csu.so`), reached through the main binary's PLT like any other imported libc
     function, something no existing strategy looked for. Its expected EXACT argument values
     are recovered by disassembling its own prologue with capstone (`mov [rbp-N], <argreg>` to
     map a stack slot to its register, then `movabs <reg>, imm64` + `cmp [rbp-N], <reg>` for the
     checked value) -- confirmed live: recovers
     `0xdeadbeefdeadbeef`/`0xcafebabecafebabe`/`0xd00df00dd00df00d` from the real `.so`, byte
     for byte, with ZERO hardcoded knowledge of the challenge; falls back to small sentinels
     when no such check exists (a `win()` that doesn't validate args, same as strategy A).
  3. `edi` (gadget2's `mov edi, r13d`) only ever gives the LOWER 32 bits of a 64-bit rdi --
     invisible on this project's own fixture (sentinels fit in 32 bits by design) but fatal
     against the real challenge's full-64-bit first argument. Fixed with a trailing
     `pop rdi; ret` after the csu tail's own epilogue, right before the final jump.
  A SEPARATE real bug surfaced testing this end to end: the shared `run()` helper (used by all
  3 strategies) sent a payload, then ALWAYS tried `io.sendline("echo MARK; id")` assuming a
  shell was spawned -- but this real `ret2win()` prints the flag and calls `exit()` itself
  (same "no shell, just a flag" pattern as the `autopoc.py` fix above, hit independently here),
  so the process had already exited by the time that followup command was sent; the resulting
  `EOFError`, caught by ONE try/except wrapping the whole function, discarded the ALREADY
  CAPTURED output -- flag included -- reporting "no verificado" for an exploit that had, in
  fact, worked. Fixed by narrowing the try/except to each individual I/O step so a failed
  followup never discards output already read, and by checking that output for a CTF-flag
  pattern (not just a shell marker) before giving up. Verified live end to end against the real
  binary: offset=40 (correct) -> `verified: True`, real flag `ROPE{Un1v3rs4l_R0P_w1th_ret2csu}`
  captured in `detail`; offsets 32/48/56 (deliberately wrong) and deliberately wrong argument
  values both -> `NOT_VERIFIED`, no false positive. `_csu_applicable`'s cheap pre-filter also
  broadened to recognize a generic gift-symbol candidate (not just `win`+`fnptr`/`retptr`) --
  updated `test_autocsu_applicable_checks_symbols_cheaply`'s negative control accordingly
  (`samples/bin/ret2win` now legitimately counts as "applicable" via the new strategy; the
  real negative is `samples/bin/leakchain`, which has no gift-named symbol and no fnptr/retptr).
  Two new regression tests
  (`test_autocsu_strategy_c_verifies_real_ropemporium_ret2csu`,
  `..._degrades_cleanly_without_a_gift_symbol`); full `autocsu`/`chainanalyzer`/`autopwn`/
  `autopivot` subset (16 tests) passes.

- **`workflows/autopivot.py`'s stack-pivot verifier generalized the same way, tested against
  ROP Emporium's real `pivot` binary.** Continuing the same real-world validation pass: the
  existing strategy (`leave; ret` into a NAMED `.bss` buffer, landing in a locally-named `win()`)
  matched none of the real challenge's shape. Added a generic strategy B:
  1. pivot gadget: the real overflow is too short even for `leave;ret` to have anything useful
     to pivot FROM -- it reaches `rbp` itself, which this exploit instead uses to carry the next
     stage's address via `pop rax; <addr>; xchg rsp, rax` (two real encodings found by byte
     pattern, like `autocsu.py`'s csu gadgets: the short accumulator form `REX.W 0x94` and the
     ModRM form `REX.W 0x87 0xc4`, both ending in `ret`).
  2. staging address: the real challenge allocates its buffer at RUNTIME and prints it
     ("The Old Gods kindly bestow upon you a place to pivot: 0x...") instead of exposing a fixed
     `.bss` symbol. Generalized to scan whatever the program prints before the first send for
     any `0x`-prefixed hex literal and use the last one found, rather than hardcoding that exact
     wording.
  3. target resolution: the real `ret2win()` isn't even IMPORTED by the main binary -- it lives
     alone in `libpivot.so`. Solved with no leak sent back to the attacker at all: find an
     "anchor" -- any function the main binary DOES import that is ALSO exported by that SAME
     library (confirmed live: the intersection of "what this binary imports" and "what
     libpivot.so exports" is exactly `{foothold_function}`, discovered purely by that
     intersection, zero hardcoded name) -- call the anchor via its own PLT (forces the dynamic
     linker to resolve its GOT entry for real), then entirely WITHIN the ROP chain: dereference
     that GOT slot (`mov rax,[rax]`) for the anchor's real runtime address, add the FIXED,
     ASLR-independent byte offset between the anchor and the target -- read once, statically,
     straight from both symbols' addresses in the `.so` file on disk (confirmed live:
     `ret2win` - `foothold_function` = 0x117 in the real library) -- and call the result. Same
     technique `autolibc.py`/`autoleakchain.py` already use for libc offsets, applied here to an
     arbitrary linked library instead of libc.
  Verified live end to end against the real `pivot` binary: offset=40 (rediscovered
  independently, matching ROP Emporium's own solve script) -> `verified: True`, real flag
  `ROPE{st4ck_p1v0t1ng_in_x64!!}` captured in `detail`. Two new regression tests
  (`test_autopivot_strategy_b_verifies_real_ropemporium_pivot`,
  `..._degrades_cleanly_without_a_cross_lib_target`); full `autopwn`/`chainanalyzer`/`autocsu`/
  `autopivot` subset (18 tests) passes twice in a row (one unrelated Wine-test flake seen once
  mid-batch -- `test_autopwn_routes_pe_binaries_to_wine_ret2win`, same pre-existing flakiness
  already documented above -- did not reproduce in isolation or on a clean full re-run).

- **`workflows/autopoc.py`'s `autorop()` ret2libc engine generalized the same way, tested
  against ROP Emporium's real `split` binary.** Continuing the same real-world validation pass:
  `autorop()` hard-required the literal string `/bin/sh\x00` (`binsh = next(elf.search(b"/bin/sh\x00"), ...)`)
  before trying ANY ret2libc strategy -- but the real challenge's already-present command string
  is `/bin/cat flag.txt\x00` (the real pattern this entire CTF series teaches: give the
  exploit-writer `system()` in the PLT and a ready-made command string, no staging needed), so
  `binsh` was always `None` and every strategy failed, reporting "no se pudo construir cadena
  automatica" against a binary that trivially has everything a ret2libc chain needs. Added
  `_find_shell_cmd_strings()`: scans the binary for ANY NUL-terminated `/bin/...` string
  (confirmed live: finds both the real `/bin/cat flag.txt` AND a decoy `/bin/ls` the same binary
  references elsewhere, for an unrelated feature), prioritizing an exact `/bin/sh` match first
  (existing behavior preserved byte-for-byte), then any string mentioning `cat`/`flag` (the real
  pattern), then the rest -- and tries ALL of them during verification, not just the first one
  that happens to build a chain. A second, more subtle bug surfaced building this: the first
  attempt passed the candidate STRING ITSELF (`bytes`) to `rop.call(sysaddr, [cmd])`, which makes
  pwntools STAGE a brand-new copy of it onto the end of the payload (an `AppendedArgument`) --
  fragile for a plain stack-overflow-over-stdin exploit, since pwntools can't know the real
  runtime stack address the appended bytes land at without more context than this driver gives
  it (confirmed live: the chain built fine but never verified -- the staged pointer just didn't
  point where the string actually ended up). Fixed by using the string's OWN EXISTING address
  (found via the same `elf.search()` used to confirm it's there), exactly like the original code
  already did correctly for literal `/bin/sh` -- no staging, no fragility. A THIRD, already-
  familiar bug (same class fixed tonight in `autocsu.py`/`autopivot.py`): the verification loop
  only checked for a shell marker echoed back over the SAME stdin pipe, but `system()` here runs
  once and the program exits right after -- nothing ever reads that trailing "echo MARK", so a
  working exploit was silently invisible to the check. Fixed by also matching a CTF-flag pattern
  in the captured output. Verified live end to end against the real `split` binary: the correct
  string is picked over the decoy, offset=40 (found by the engine's own dynamic search, no
  hint given) -> `verified: True`, real flag `ROPE{split_ret2libc_in_x64}` captured; a
  deliberately wrong offset (20) -> `verified: False`, no false positive. Two new regression
  tests (`test_autorop_verifies_real_ropemporium_split_with_non_binsh_string`,
  `..._negative_control_wrong_offset_real_split`); full `autopoc`/`autopwn`/`autorop`/
  `chainanalyzer` subset (16 tests) passes.

- **New primitive: `workflows/autocallme.py`, a distinct shape from everything above, found
  continuing the same real-world ROP Emporium validation pass.** Its `callme` challenge doesn't
  fit `autocsu.py` (gadget-poor, needs the csu trick) or `autopoc.py`/`autorop()` (one gift
  target): the binary is gadget-RICH (a plain `pop rdi; pop rsi; pop rdx; ret` exists), but the
  gift is split across THREE functions (`callme_one`/`two`/`three`, each validating its own
  fixed 3 arguments, each living in a separate shared library like `autocsu.py`'s ret2csu
  target), and -- confirmed live -- calling them in the WRONG order (alphabetical: one, three,
  two) silently corrupts the resulting flag instead of failing cleanly; there's no reliable
  name-based rule to infer the right order generically ("one/two/three" is this one challenge's
  own convention). New module tries every ORDERING of the discovered targets (cheap: 3 is 6
  permutations, capped at 4 targets / 24 permutations) instead of guessing one. Target discovery
  has two levels: by gift-keyword name first (same heuristic `autopoc.py`/`autocsu.py` already
  use), then, since `callme_one/two/three` match NONE of those keywords at all, by STRUCTURE --
  any function whose own body `autocsu._infer_fixed_args` recognizes as "validates registers
  against fixed constants," with no naming assumption whatsoever.
  Building the structural fallback surfaced a real, SHARED latent bug in
  `autocsu._infer_fixed_args` itself (used by both `autocsu.py` and this new module): it
  disassembled a fixed 0x300-byte window from each candidate's address with no bound on the
  function's own size, so scanning EVERY function in `libcallme.so` produced 4 false positives
  (`deregister_tm_clones`/`register_tm_clones`/`__do_global_dtors_aux`/`frame_dummy` -- tiny CRT
  boilerplate, none of which actually check anything) all "recognized" as checking the exact
  same 3 values as the real `callme_one`, which sits only 10 bytes after `frame_dummy` -- the
  disassembly simply ran past the tiny function's own `ret` into its neighbor's bytes and
  attributed them to the wrong symbol. This was invisible on `autocsu.py`'s own single-target
  use (`ret2win` there is large enough that 0x300 bytes never reaches a neighbor) but a real
  correctness bug for a function meant to be reused across arbitrary candidates. Fixed by adding
  an optional `size` parameter (the symbol's own `st_size`) that bounds the disassembly window
  to the function's real body; the existing single-target call site is untouched (doesn't pass
  `size`, same behavior as before, confirmed by the full existing `autocsu` suite still passing).
  Verified live end to end against the real `callme` binary: exactly the 3 real functions found
  (no CRT false positives), the brute-forced ordering search lands on the correct one (one, two,
  three) and returns the real flag `ROPE{C4ll1ng_w1th_params_1n_x64}`; a binary with only one
  gift function (`ret2win.c`) correctly finds nothing and reports NOT_APPLICABLE, not a forced
  match. Wired into `autopwn()`'s combo orchestrator (`want("callme")`, tried after the
  single-target strategies, same pattern as `ret2csu`/`pivot`) and into `_why()`'s rationale
  strings. Two new regression tests
  (`test_autocallme_verifies_real_ropemporium_callme_with_correct_order`,
  `..._degrades_cleanly_with_a_single_gift_function`); full `autopoc`/`autopwn`/`autorop`/
  `chainanalyzer`/`autocsu`/`autopivot`/`autocallme` subset (28 tests) passes clean.

- **CI flake diagnosed and fixed: `test_autocanary_verifies_leakable_sample` (run #202, commit
  `bbfe407`).** Root-caused, not assumed flaky: that commit's own diff touches only
  `autopoc.py`/`tests/test_smoke.py`, nothing in `autocanary.py` or `samples/`; the test passed
  3/3 on a clean local re-run; and it passed in every OTHER CI run tonight before and after this
  one. The likely trigger: three `workflow_dispatch` runs (#201/#202/#203) were fired back to
  back without waiting for each to finish, landing concurrently on GitHub's shared runner pool --
  resource contention under that is a well-known source of exactly this symptom (a real
  subprocess I/O `recv()` with a tight, hardcoded `timeout=2` just missing its window on a loaded
  box, not a logic bug). Fixed defensively regardless of the exact trigger: bumped the leak read's
  two `timeout=2` calls to `timeout=4` (comfortably above the driver's own `context.timeout = 3`
  default) -- cheap insurance against the next loaded run, at worst +2s per one of the up to 78
  bufsz/rbpgap/align combinations this driver sweeps (only on combinations that were going to
  fail anyway). Going forward: don't fire overlapping `workflow_dispatch` runs back to back --
  wait for one to land before triggering the next.

- **New primitive: `workflows/autowrite4.py` (write-what-where + call), found continuing the
  same real-world ROP Emporium validation pass.** `chainanalyzer.analyze_chains()` found NO
  feasible chain at all for the real `write4` binary (score 0 across every existing kind) -- a
  genuine missing primitive, not a verification-layer gap like `ret2csu`/`pivot`/`callme`: this
  binary has no useful pre-existing string and no gift function reachable by jumping anywhere,
  but it DOES expose a `pop r14; pop r15; ret` + `mov [r14], r15; ret` gadget pair, enough to
  write 8 attacker-chosen bytes to any address and repeat for a longer string. New module:
  1. gadgets found by byte pattern (like `autocsu.py`'s csu gadgets), starting with the
     confirmed-live r14/r15 pair (extensible to more pairs without touching the rest of the
     module).
  2. the staging address needs no named symbol or hardcoded `.data` offset -- `ELF.bss()`
     (pwntools) already gives a safe, writable address for free.
  3. the target (`print_file`) matches no gift keyword and validates no fixed argument -- found
     STRUCTURALLY instead: disassemble every candidate function (local, or if none, imported
     from a linked `.so` like `autocsu.py`'s strategy C) with capstone and check whether it
     forwards its own first argument into a call to `fopen`/`open`, the same shape ANY
     "read-and-print-a-file-by-path" function has, confirmed live to find exactly `print_file`
     (which lives in `libwrite4.so`, not the executable) and nothing else.
  4. since there's no leak to recover the real filename from, a short list of common CTF
     flag-file names is tried (`flag.txt`, `flag`, `/flag.txt`, `/flag`), each chunked into
     8-byte writes and NUL-padded to the next multiple of 8 -- a wrong guess just fails to
     verify, never a false positive.
  Verified live end to end against the real `write4` binary: writes `flag.txt` to a fresh `.bss`
  address, calls the real `print_file` with it, and returns the real flag
  `ROPE{WR1t34_in_x64_data_section}`; a binary with no write-gadget pair (`ret2win.c`) correctly
  finds nothing. Wired into `autopwn()`'s combo orchestrator (`want("write4")`, tried after
  `callme`) and into `_why()`. Two new regression tests
  (`test_autowrite4_verifies_real_ropemporium_write4`,
  `..._degrades_cleanly_without_the_write_gadget_pair`); full `autopoc`/`autopwn`/`autorop`/
  `chainanalyzer`/`autocsu`/`autopivot`/`autocallme`/`autowrite4`/`autocanary` subset (31 tests,
  1 skipped for a missing 32-bit multilib sample) passes clean.

- **New primitive: `workflows/autobadchars.py` (write-what-where PAST an input byte filter),
  found continuing the same real-world ROP Emporium validation pass -- the last and hardest step
  up from `autowrite4.py` in this series.** The real `badchars` binary filters the ENTIRE input
  for 4 forbidden bytes (confirmed live: exactly `b"xga."`, read straight from the binary's own
  `badcharacters` data symbol with zero prior knowledge, matching ROP Emporium's own published
  solve.py byte for byte) before processing it -- not just the string being written, EVERY byte
  of the payload, gadget addresses included, with any match silently replaced. `autowrite4.py`
  would get its raw string write corrupted here (its target string's own bytes -- "flag.txt" --
  are exactly the forbidden set, by design: the challenge's whole point is that you CAN'T write
  it raw). Solved by XOR-encoding: pick a key (brute-forced over 1..255, not guessed) that keeps
  both the key byte and every byte of the encoded string out of the forbidden set, write the
  ENCODED bytes (which the filter lets through untouched, since none of them match), then
  XOR-decode each byte back to its real value IN PLACE using a `xor [r15], r14b; ret` gadget --
  the filter only ever runs on the incoming payload, never on the target's own memory afterward.
  A real correctness requirement surfaced building this that's easy to miss: since the filter
  covers the WHOLE payload, every address the chain places on the stack (every gadget, the
  staging address, the target function) has to be checked byte-by-byte against the forbidden set
  too, not just the string -- an address that happened to contain a forbidden byte would get
  silently corrupted mid-chain with no obvious symptom besides "didn't work." Reused
  `autowrite4.py`'s structural target-finding (`print_file`, same function, same shape) and
  filename-guessing list unchanged. Verified live end to end: auto-discovers the forbidden-byte
  set, the gadget quartet (`pop r12/r13/r14/r15`, `pop r14/r15`, `mov [r13],r12`,
  `xor [r15],r14b`, all by byte pattern), and a key (2, independently rediscovering ROP
  Emporium's own solve.py's choice) that encodes "flag.txt" past the filter, then decodes and
  prints it for the real flag `ROPE{XORing_1n_d4ta_s3ct10n_x64}`; a binary with no forbidden-byte
  symbol (`ret2win.c`) correctly finds nothing. Wired into `autopwn()`'s combo orchestrator
  (`want("badchars")`, tried after `write4`) and into `_why()`. Two new regression tests
  (`test_autobadchars_verifies_real_ropemporium_badchars`,
  `..._degrades_cleanly_without_a_badchars_symbol`).

- **Real false-positive bug found in `heap_dynamic.py`'s and `frida_dynamic.py`'s
  `glibc_also_aborted` double-free confirmation, testing against a real how2heap binary
  (shellphish/how2heap's `glibc_2.39/tcache_house_of_spirit.c`, not a synthetic fixture of this
  project).** Both backends' `heap_confirm_double_free` marks the independent-confirmation field
  `glibc_also_aborted` by searching the captured output for the loose substrings `"double free"`
  / `"corrupt"`. The real how2heap binary's own EDUCATIONAL printf text literally contains the
  phrase "double free or corruption" -- as a search hint describing the general concept, not a
  claim that it happened -- so both backends reported `glibc_also_aborted: True` even though the
  technique it demonstrates (freeing a forged stack chunk, confirmed independently as a genuine
  `verified: True` -- "a direccion se libera sin estar viva, nunca asignada en esta ejecucion")
  does NOT actually make glibc abort: the process exits normally (confirmed live: exit code 0,
  its own `assert()` passes) and gdb's log ends in "[Inferior 1 (process N) exited normally]",
  never a real signal. Fixed with a precise regex (`_GLIBC_FATAL_ERROR_RE`, shared between both
  oracles) matching the EXACT prefix glibc's own malloc/free fatal-error reporter uses
  ("free(): ", "malloc(): "...) -- a format no ordinary program replicates, confirmed live
  against both a real abort (a naive double-free: "free(): double free detected in tcache 2",
  matched) and the how2heap binary (not matched, since it only quotes the bare words as a search
  hint, never that exact prefixed format). Tried and discarded two other fixes along the way:
  gdb's "Program received signal SIGABRT" line (worked for the gdb backend, but `frida_dynamic.py`
  has no equivalent -- it only captures the inferior's own stdout/stderr, never a debugger's own
  diagnostic text) and Frida's own `on_detached(reason, crash)` callback (confirmed live that
  `reason` is "process-terminated" for ANY process ending in this environment, crash or clean
  exit alike, and `crash` stays `None` even for a confirmed real SIGABRT -- neither distinguishes
  anything here). Verified live end to end on both backends: the real how2heap binary now
  correctly reports `glibc_also_aborted: False` (still `verified: True` -- the primary
  determination, from the actual malloc/free interception replay, was never affected); a genuine
  double-free still correctly reports `True`. Two new regression tests, one per backend
  (`test_heap_dynamic_does_not_false_flag_educational_text_as_a_real_glibc_abort`,
  `test_frida_dynamic_...`), embedding the real how2heap source directly (short, dependency-free,
  so the test needs no external clone); full `heap_dynamic`/`frida_dynamic` subset (16 tests)
  passes clean, including the two pre-existing tests that already expected `True` for this
  project's own `samples/bin/heapbug` fixture (confirmed unaffected: that fixture's real crash
  message passes the new, more precise check too).

- **Real gap found running binoracle end to end against a genuine, unread public reversing CTF
  binary -- a different kind of validation than the exploitation-focused ROP Emporium series:
  this one tests whether binoracle's STATIC/grounded tooling (no exploit, no shell -- just
  read the binary) actually helps solve a "find the flag" challenge, and it does, but a real
  gap turned up in one specific tool along the way.** Picked a real competition binary blind
  (ShadowCTF 2021's "Intro" crackme, via the `Kasimir123/CTFWriteUps` mirror, the solution
  unread until after solving it independently) and ran `binoracle secrets` (the credential/IOC
  scanner, `workflows/iocscan.py`, built as REA parity) against it first. It reported "sin
  credenciales detectadas" -- but the binary's ENTIRE challenge is a flag sitting in plain text
  among its strings (`{steppingstone}`; the published writeup solves it with nothing more than
  `strings`). The scanner's patterns are all for REAL credentials (AWS/Stripe/GitHub/Slack
  keys...) -- there was no pattern at all for the single most common shape a CTF/malware
  analyst specifically also wants surfaced: a `name{...}` or bare `{...}` flag/marker string.
  Added `ctf-flag` (two forms, content restricted to alnum/underscore/hyphen so it can't swallow
  a code or JSON snippet that happens to contain braces) and excluded it from the "secret_kinds"
  / redaction treatment the real credential kinds get -- a flag is something you want to see in
  full, not a leak to mask and rotate. Verified live: finds exactly the one real flag in the real
  binary; finds NOTHING in a second real CTF binary (ROP Emporium's `split`, reused from
  earlier tonight) whose flag is genuinely absent as plain text (confirming no over-eager false
  positive); stays clean against `/bin/ls`/`/bin/bash`; a large, unrelated interpreter binary
  (`/usr/bin/python3.13`, full of embedded bytecode) does produce some noise (~16 candidates,
  mostly obvious byte-garbage) -- acceptable for an explicitly-heuristic scanner meant to be
  eyeballed, same as every other pattern in this module, and bounded by the existing
  `max_hits_per_kind` cap. Separately, confirmed `explain`/`ask`/`hunt`/`primitives`/`chat` all
  genuinely require a reachable local model (`binoracle doctor` reported none in this
  environment) -- unlike `triage`/`secrets`/`identify`, they are not "grounded-only with the
  model as an optional narrator" the way some of the README's phrasing could be read; the actual
  reversing (recovering the flag via the binary's own disassembly, read directly) still worked
  using the SAME grounded facts those commands would have handed to a model, just reasoned over
  directly instead of through that pipeline. A second, harder real challenge from the same
  mirror (RaRCTF 2021's `verybabyrev`, an in-place XOR-chain cipher, no plaintext flag anywhere)
  was solved the same way end to end and the recovered flag matched that challenge's own
  published writeup exactly. Two new regression tests
  (`test_ioc_scan_finds_ctf_flag_both_prefixed_and_bare`,
  `test_ioc_scan_finds_real_ctf_flag_in_real_shadowctf_binary`); full `secrets`/`ioc_scan`
  subset (5 tests) passes clean.

- **Real gaps found running binoracle's Android audit (`androidaudit.py`/`workflows/apkinspect.py`/
  `secrets`) end to end against a REAL, fully-working install of MobSF (Mobile Security Framework,
  the established open-source mobile pentest tool: cloned upstream, `poetry install`'d with its
  full dependency set -- androguard, apktool, JADX, frida, mitmproxy, yara... -- migrated and run
  as a local server) and two genuinely third-party, deliberately-vulnerable Android apps: OWASP's
  own `InsecureBankv2` (cloned from `dineshshetty/Android-InsecureBankv2`) and `Fit32.apk` (the
  Trellix "Killer-App" CTF challenge, already in this environment's CTF-writeup mirror). The goal
  was the question the user actually asked: is binoracle's own Android support any good, measured
  against a real, independently-maintained tool on real vulnerable targets -- not against a
  synthetic fixture. Three concrete gaps turned up, all now fixed:
  1. **`binoracle audit some.apk` refused to even start.** `cmd_audit` called
     `make_backend(config).available()` and hard-exited(3) with "no local model reachable" for
     EVERY target before dispatching -- but `run_android_audit` (what `run_audit` routes an APK
     to) is 100% grounded/static and never touches the LLM at all; the gate made zero sense for
     Android and, with no local model reachable in this environment (confirmed earlier via
     `binoracle doctor`), made the entire Android audit path unusable from the CLI, full stop.
     Fixed: `cmd_audit` now checks `_is_apk(binary)` first and skips the backend probe entirely
     for APK targets. Confirmed live: `binoracle audit InsecureBankv2.apk` now runs to completion
     with no model reachable and reports 14 real findings (4 high/5 medium/2 low/3 info) --
     `android:debuggable=true`, `android:allowBackup=true`, 7 exported components (activities/
     receiver/provider with no permission), a hardcoded-looking `System.out.println("newpassword="
     + ...)`, a `rawQuery(... + str ...)` SQL-injection-shaped call, `addJavascriptInterface`/
     `setJavaScriptEnabled(true)` on a WebView, `Runtime.exec("which su")`, weak MD5/SHA-1 hashing
     and logging -- which, cross-checked against the SAME app scanned by the real, fully-working
     MobSF install in this session, is MORE findings than MobSF's own static scan surfaced for
     the comparable Fit32.apk CTF target (MobSF: 2 manifest + 2 code findings there; binoracle's
     own `androidaudit.py` already had MASVS-RESILIENCE/biometric-CryptoObject checks MobSF
     doesn't even attempt).
  2. **Real OWASP MASVS/MASWE + CWE taxonomy data was computed, attached to every `Finding`,
     persisted to the DB (`owasp`/`cwe` columns already existed) -- and then silently dropped by
     `render_findings()`, which never printed those two fields.** Separately, `render_agent_result`
     unconditionally appended an "OWASP Desktop Top 10" coverage table to EVERY audit report,
     Android included -- a desktop-app framework, nonsensical for a mobile APK, confusingly
     layered on top of findings that already carry their own correct MASWE IDs per-finding.
     Fixed both: `render_findings` now prints a `taxonomy:` line (`MASWE-xxxx · CWE-yyy`) per
     finding when either is set; `render_agent_result` skips the Desktop Top 10 table when
     `stopped_reason == "android-audit"` rather than invent a half-verified Mobile-Top-10 mapping
     to replace it with (a real per-category MASVS/MASWE coverage table is a natural follow-up,
     deliberately left as a TODO rather than shipped unverified -- the MASWE catalog itself just
     went through a v1.0.0 renumbering in August 2026, consolidating 119 IDs down to 78, so a
     coverage table built from today's IDs needs re-checking against that, not a guess).
  3. **`binoracle secrets`/`iocscan.py` found nothing useful on a real APK.** An APK is a ZIP;
     `scan_iocs` reads the file's raw bytes and extracts printable strings from THOSE bytes --
     but a ZIP's actual file contents are DEFLATE-compressed, so a flat strings scan only ever
     sees the (mostly useless) central-directory filename table. Confirmed live: the real,
     fully-working MobSF install's own secrets scanner found ~24 high-entropy base64-looking
     strings (AES keys/IVs embedded in InsecureBankv2's decompiled resources/Java) in the same
     APK that `binoracle secrets` reported zero useful hits on. Added `_expand_zip`: when the
     scanned file is a valid ZIP (APK/JAR/AAR/plain .zip), each inner entry's DECOMPRESSED bytes
     are appended to the scan buffer (bounded: <=4000 entries, <=8MiB/entry, <=64MiB total, so a
     zip bomb can't make this unboundedly slow or exhaust memory) -- decompressed content FIRST,
     the outer ZIP's own bytes last, so the central-directory filename-table noise never crowds
     out real findings. Caught and fixed one own mistake along the way: the `high_entropy`
     bucket's first-seen-wins 30-item cap meant even with the right scan ORDER, moderate-entropy
     structured resource-table strings (`@style/...`, `res/layout/...`) that happen to appear
     before the real secrets in byte order still filled the cap first; switched it to collect a
     larger pool and keep the top-30 BY ENTROPY instead of by arrival order. Verified live,
     end to end: `binoracle secrets InsecureBankv2.apk` now surfaces the exact same base64
     strings MobSF's independent scan reported for this same real app, ranked at the top of the
     high-entropy bucket. Three new regression tests
     (`test_cmd_audit_on_apk_never_requires_a_local_model`,
     `test_render_agent_result_skips_desktop_owasp_for_android_and_shows_taxonomy`,
     `test_ioc_scan_expands_zip_to_find_secrets_invisible_in_raw_compressed_bytes`,
     `test_ioc_scan_finds_real_secrets_in_real_vulnerable_apk` -- the last one skips cleanly if
     the external APK isn't present, same pattern as the existing ShadowCTF regression test).

- **Fourth gap from the same Android/MobSF testing round: `binoracle apk` (the "quick facts"
  command, `apkinspect.py` -- deliberately dependency-free, zipfile only, nothing executed)
  kept advertising "AndroidManifest.xml is binary: detected but not decoded" as a blanket
  limitation even on a real target where apktool IS installed and `binoracle audit`
  (`androidmanifest.py`) already decodes it perfectly** -- confusing for anyone who runs the
  "quick" command first and never learns `audit` exists. `inspect_apk` now opportunistically
  calls `project_mobile_application_graph` (same honest degrade-when-apktool-absent pattern used
  everywhere else in this codebase) and, when it succeeds, surfaces `manifest_package`/
  `manifest_permissions`/`manifest_component_count`/`manifest_exported_count` and rewrites the
  limitation note to point at `binoracle audit` for the full breakdown instead of implying the
  manifest can never be decoded. Confirmed live on InsecureBankv2.apk: `binoracle apk` now shows
  `paquete: com.android.insecurebankv2 | componentes: 13 (exportados: 7) | permisos: 9` instead of
  nothing. New test (apktool stubbed, same pattern as the existing `androidmanifest.py` tests);
  the pre-existing synthetic-APK test (fake, non-decodable AXML bytes) is unaffected -- apktool
  fails to decode it, so the enrichment silently stays off, exactly as before.

## Explicitly out of scope

- Weaponization against real third-party systems. Everything stays for authorized software,
  CTF challenges, lab malware, and authorized engagements.
- Turn-key malware payload kits.
- A dedicated primitive for ROP Emporium's `fluff` challenge (the last of this series left
  untouched after `ret2win`/`ret2csu`/`pivot`/`callme`/`ret2libc`/`write4`/`badchars`, all now
  covered). Looked at it and deliberately passed: it decodes "flag.txt" one byte at a time with
  `bextr`+`xlat`+`stosb`, where the FIRST byte's decode depends on whatever happened to be left
  in `AL` by an earlier library call (`puts()`'s return count, in the real binary) -- a genuinely
  runtime-dependent detail with no clean static recovery, only a 256-way brute force or
  hardcoding this one binary's own behavior. Unlike every primitive added above, it isn't a
  pattern that generalizes to real-world exploitation -- it's a deliberately exotic "look what
  weird gadgets can do" teaching gimmick specific to this one challenge. Lower value for the
  implementation cost; not pursued.
