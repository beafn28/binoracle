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
- **[S-M] CFI / SafeStack / ASan reasoning.** Turn detection into grounded bypass-strategy
  hints (still not auto-bypass), tied to the observed hardening.

## v0.3 - Verified exploits, not just verified reachability

The flagship direction: prove impact end to end.

- **[L] Auto-PoC generation.** From a verified crash, synthesize a runnable pwntools exploit
  (ret2win first, then ROP / ret2libc) and *run it in the sandbox* to confirm a shell or the
  flag. "Verified exploit" becomes a real verdict above "verified reachability".
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
