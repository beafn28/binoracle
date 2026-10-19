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
  unsafe-unlink and tcache-stashing glibc-internals techniques) were NOT in autopwn's own
  applicability/decision tree -- each needs its own `_xxx_applicable()` detector analogous to
  the existing heap ones before autopwn can try them autonomously. Two closed in a follow-up
  pass: `_csu_applicable()` (needs `win`+`fnptr`, or `retptr` for the execve variant) and
  `_pivot_applicable()` (needs a win/gift-like symbol AND a known `.bss` staging-buffer symbol)
  added, both cheap pyelftools symbol pre-checks matching the existing `_heap_shell_applicable`/
  `_uaf_applicable` convention; `ret2csu` and `pivot` wired into `autopwn()`'s combo sequence
  (tried before the generic ROP sweep, since ret2csu's whole point is having no pop rsi/pop rdx
  of its own) and `_why()`'s rationale, verified end-to-end through the ORCHESTRATOR itself
  (not just the standalone module) against `samples/bin/ret2csu` and `samples/bin/pivot`.
  Still open: the remaining 12 (house-of-*, IO_FILE/FSOP, fastbin-dup, unsafe-unlink,
  tcache-stashing) -- each is its own, more involved applicability check (glibc-internals
  preconditions, not just symbol presence) and still needs a dedicated pass.
- **[M] Frida dynamic oracle.** Cross-platform, scriptable hooks (heap tracing, function
  interception) to augment/replace gdb/lldb.
- **[L] Concolic loop.** Drive angr from a real dynamic trace (symbolic-assisted crash
  triage), so verification scales past toy binaries.
- **[M] Windows PE dynamic + symbolic.** Wine sandbox for `dbg_run_input`, and SimProcedures
  for the MSVCRT/mingw runtime so `angr_reachable` works properly on PE.

## v0.4 - Scale, formats, n-day

- **[M] Patch-diff v2 (n-day).** LLM classifies the "silent security fix" in a radiff2 diff
  and auto-generates a regression test. Shadow-CI for binaries.
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
