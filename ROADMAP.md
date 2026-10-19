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
  don't fire on kernel copy_to/from_user. Still open: chunk/bin analysis and the
  tcache/fastbin-poisoning primitive suggester.
- **[M] ROP builder v2.** Leak-aware chains (auto ret2libc once a leak step exists),
  `one_gadget` integration, `mprotect`+shellcode chains, SROP, and a `ropper` backend as an
  alternative to pwntools.
- **[M] Automatic infoleak chaining.** Wire a format-string / OOB-read leak into a follow-on
  GOT-overwrite or ROP as a *single* verified chain, not two separate findings.
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
