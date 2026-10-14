# binoracle — The Engine

*A grounded binary-analysis and exploit-development engine. Nothing is called
`verified` without a real shell in a sandbox; every report carries its evidence
and its `limitations`.*

---

## 1. What this document is

This is the single professional overview of the complete binoracle engine. It
covers three pillars:

1. **The static grounding core** — readers that *describe* a binary and never
   execute it. Full parity with (and a superset of) the surfaces in
   `morluto/rea`.
2. **The exploit-development engine** — execution-verified exploit builders for
   ~19 stack/ROP and heap technique families, in both x86-64 and x86-32.
3. **Runtime / external connectors** — a separate dynamic module (adb / Frida /
   browser) and caller-supplied decompilers (Ghidra headless, JEB) that run
   only against authorized targets and whose output is treated as untrusted.

The design rule that governs the whole project: **grounding by execution.** A
claim is `verified` only when the engine produced the stated effect — almost
always a real shell — inside a sandbox and read back the proof. Everything
else degrades honestly to `feasible`, `not_verified`, or `not_applicable`,
and reports always name their `limitations`.

> **Authorization.** The exploit engine and the dynamic module are for
> AUTHORIZED security testing, CTF, and research only. Static readers never
> execute the target. Uploaded binaries, external code, and tool output are
> treated as untrusted data.

---

## 2. The verified exploit engine

Every technique below has a dedicated verifier (`binoracle/workflows/auto*.py`),
an intentionally-vulnerable practice sample (`samples/src/*.c`, built by
`samples/build.sh`), an MCP tool, and a CLI subcommand. "Verified" in the
`Proof` column means the engine actually popped a shell (or produced the named
primitive effect) in the sandbox and read back a marker / `uid=` line.

### 2.1 Stack & control-flow hijack

| Technique | Arch | Verifier | Sample | What is proven |
|---|---|---|---|---|
| **ret2win** | x86-64, x86-32 | `autopoc` | `ret2win`, `ret2win32` | Overflow → redirect to `win()`; offset found by execution, marker read back |
| **ret2libc (leak)** | x86-64 | `autolibc` | `ret2libc` | Leak libc via puts@plt → return into `system("/bin/sh")`, SysV arg in `rdi` |
| **ret2libc (cdecl)** | x86-32 | `autolibc` / chain | `ret2libc` | 32-bit cdecl stack args: `system` + fake ret + `&"/bin/sh"` |
| **execve by syscall** | x86-64, x86-32 | `autopoc` (step 2) | `srop`, `srop32`, `staticrop` | x64 `syscall` execve=59; x86 `int 0x80` execve=11 — full register setup by ROP |
| **SROP** | x86-64, x86-32 | `autosrop`, `autopoc` | `srop`, `srop32` | Forged sigreturn frame → execve. i386 needs explicit segment selectors (cs=0x23/ss=0x2b/ds=es=0x2b/gs=0x63) — proven, not assumed |
| **ret2csu (call)** | x86-64 | `autocsu` (mode=win) | `ret2csu`, `csuexec` | Universal `__libc_csu_init` gadgets control rdi/rsi/rdx and make a 3-arg call |
| **ret2csu → execve** | x86-64 | `autocsu` (mode=execve) | `csuexec` | csu sets rsi/rdx, benign call, then pop rdi=/bin/sh / pop rax=59 / syscall |
| **ret2dlresolve** | x86-64 | `autodlresolve` | `dlresolve` | Shell on a dynamic no-PIE Partial-RELRO binary with **no libc leak and no gift** |
| **stack pivot** | x86-64 | `autopivot` | `pivot` | Short overflow → migrate the stack to `.bss` via `leave;ret`, then run a full chain |
| **format-string** | x86-64, x86-32 | `autofmt` | `fmtstring`, `fmt_got`, `fmtgot32` | `%n` GOT overwrite → `system`; handles Partial & Full RELRO; robust probe with retry |
| **canary bypass** | x86-64 | `autocanary` | `canleak`, `canfmt` | Leak the canary (via `%s`/`%p`), re-plant it, then overflow past it to a shell |

### 2.2 Heap

| Technique | glibc basis | Verifier | Sample | What is proven |
|---|---|---|---|---|
| **tcache poisoning** | real ≥2.32 (safe-linked) | `autoheap` / chain | `notes_heap`, `heapexp` | Forge a safe-linked `fd` → arbitrary alloc → overwrite a function pointer → shell |
| **tcache dup** | real ≥2.34 | `autotcachedup` | `heapbug` | Double-free → `free@GOT = system` → shell (no `__free_hook`) |
| **UAF (funcptr)** | real | `autouaf` | `uaf` | Chunk reuse without poisoning tcache → hijack a stored function pointer |
| **write-what-where** | n/a (OOB) | `autowow` | `oobwrite`, `intoverflow` | Unchecked index / OOB write → GOT overwrite → shell |
| **house-of-force** | pre-2.29 (reproduced) | `autohof` | `hof` | Top-chunk size overwrite → arbitrary alloc. The ≥2.29 top-size check is documented; the pre-2.29 allocator is reproduced **in the binary** so the primitive runs end-to-end |
| **house-of-spirit** | real 2.39 | `autohos` | `hos` | Forge a fake chunk straight into the real glibc tcache → arbitrary alloc → shell |
| **house-of-einherjar** | reproduced | `autohoe` | `hoe` | Backward consolidation via a crafted `prev_size` + off-by-null, reproduced in-binary |
| **house-of-botcake** | real 2.39 | `autobotcake` | `botcake` | Double-free routed through the **unsorted bin** to clear the tcache key → chunk overlap → safe-linked tcache poison → shell |
| **largebin attack** | ≥2.30 (reproduced) | `autolargebin` | `largebin` | Corrupt a largebin chunk's `bk_nextsize` so a later large-chunk insertion runs `victim->bk_nextsize->fd_nextsize = victim` → arbitrary pointer write → hijack → shell |
| **tcache stashing unlink** | ≥2.31 (reproduced) | `autostash` | `stash` | Smallbin→tcache stash with a corrupted `bk` stashes a **fake chunk** → later alloc returns an attacker address → hijack → shell. Reproduces **and satisfies** the ≥2.31 `bck->fd == tc_victim` check (calloc trigger) |

**Honest notes on the heap families.** house-of-spirit and house-of-botcake
run against **real, modern glibc (verified on 2.39)** — they defeat the current
tcache double-free key and smallbin hardening. house-of-force,
house-of-einherjar, and the largebin attack are blocked on modern glibc by
well-known checks (top-chunk size check ≥2.29; backward-consolidation checks;
the ≥2.30 `bk_nextsize` sanity check); binoracle **documents the mitigation**
and then reproduces the classical allocator behaviour **inside the practice
binary** so the primitive still executes and is observable end-to-end, rather
than silently claiming a bypass that modern glibc would refuse. This is the
honest-degradation rule applied to the heap.

### 2.3 Why these actually run: the grounding mechanics

- **Sandbox.** `binoracle/workflows/_sandbox.py::run_driver` runs each pwntools
  driver inside the `binoracle-pwn` Docker image, or falls back to a native
  `unshare` sandbox when Docker is unavailable (`native_available()`). If
  neither is present the tool degrades to `not_verified` — it never fakes a
  pass.
- **ASLR off → determinism.** The sandbox disables ASLR, so the heap base and
  loaded symbol addresses are fixed. Where a classical write-up would need an
  info leak, binoracle instead reads the exact value from `/proc/<pid>/mem` at
  the known symbol, keeping the *technique* honest while removing leak flakiness
  from the *verification*.
- **Safe-linking.** For every modern-glibc heap verifier the forged `fd` is
  mangled as `target ^ (chunk_addr >> 12)` (glibc ≥2.32), computed from the
  real runtime heap address — not hard-coded.
- **Markers.** A shell is confirmed by sending `echo <MARK>; id` and matching
  the marker or a `uid=` line in the captured output. No marker, no `verified`.

---

## 3. The chain analyzer & ROP arsenal

`binoracle/workflows/chainanalyzer.py` is the ROP brain. It is **arch-aware**
(`_is32`, `_arg_regs`, 32-bit arg order `ebx,ecx,edx,esi,edi,ebp`, `int 0x80`
terminator) and builds, not just lists, exploit chains.

- **Gadget classifier** (`_classify`) computes a precise stack delta from the
  width of popped registers, and recognises write-what-where (comma-split
  operands), register moves, pivots (including `esp`), and both syscall
  terminators.
- **Arsenal** (`_build_arsenal` / `_full_arsenal`) selects, per argument
  register, the best gadget; finds the syscall/pivot/write primitives; and
  reports **execve coverage** — whether the register setup needed for a
  `execve("/bin/sh",…)` syscall is reachable from the available gadgets.
- **ret2csu detection** (`_detect_ret2csu` / `_find_csu_gadgets` /
  `_parse_csu`) locates the universal `__libc_csu_init` gadgets by linear
  disassembly (`pd`), tolerant of r2's Unicode graph prefixes and symbol-gated
  so it never hangs on a stripped entry.
- **Chains as a graph.** SROP and ret2csu are first-class `ExploitChain`
  objects verified end-to-end (`_verify_chain`, kinds include `"csu"`); the
  32-bit path is proven (VERIFIED ret2win at offset 72 and ret2libc `system`
  at offset 76 on the 32-bit corpus).

The standalone heap/pivot verifiers (`autopivot`, `autohof`, `autohos`,
`autohoe`, `autobotcake`) are *practice-shaped* (they rely on a specific menu
or symbol layout), so they stay as dedicated execution verifiers rather than
being forced into the generic gadget graph; the graph owns the ROP/syscall
families where a generic chain is meaningful.

---

## 4. Static grounding core — full REA parity (and more)

These readers **describe** an artifact and never execute it. They match the
surfaces of `morluto/rea` and add several it does not cover. (REA is MIT; its
ideas were re-implemented in Python with attribution, not copied.)

| Surface | Reader | Notes |
|---|---|---|
| ELF layout | `elflayout`, `_binfacts` | sections, segments, symbols, RELRO/NX/PIE/canary |
| Go binaries | `goinspect` | buildinfo, module graph, pclntab functions |
| WASM | `wasminspect` | sections, imports/exports, function table |
| SQLite | `sqliteinspect` | schema, pages, embedded blobs |
| EVM bytecode | `evminspect` | opcode disasm, selectors, storage layout |
| .NET assemblies | `dotnetinspect`, `dotnet` | metadata, types, IL |
| Mach-O | `machoinspect` | load commands **+ Objective-C & Swift metadata** (classes, methods, protocols) |
| PE | `peinspect` | imports/exports, sections, resources |
| APK | `apkinspect` | manifest + decompile path |
| Java / JAR | `jarinspect` | classes, manifest, constant pool |
| JavaScript / Electron | `jsinspect` | bundle/entrypoint analysis; `recover_javascript_sources` rebuilds the original source tree from a `.js.map` `sourcesContent` (path-traversal-safe) |
| **Flutter / Dart AOT** | `flutterinspect` | resolves `_kDart*Snapshot*` symbols (section `.dynsym` **or** stripped-`ET_DYN` PT_DYNAMIC), maps them through PT_LOAD, parses each **snapshot header** — version hash (SDK/engine revision) + features string → **target arch** (x64/arm64/…) and **runtime mode** (product/profile/release); the **libflutter.so engine** (build-id revision, Dart version line, Impeller/Skia backend, Vulkan/GLES API, toolchain); and the **flutter_assets** bundle (AOT vs debug/JIT; **AssetManifest.bin decoded via a bounded StandardMessageCodec reader** — declared assets + variant count; FontManifest fonts, shaders, NOTICES, version.json); plus ELF arch, per-ABI, Dart VM version (absence reported, not guessed) |
| ASAR (Electron) | `asarinspect` | archive listing + file extraction |
| macOS plist | `plistinspect` | binary & XML plists |
| HAR captures | `harinspect` | request/response, secrets scan |
| Firmware | `firmware_scan` | embedded filesystem / blob carving |
| **RF / logic signals** | `signal_decoders`, `decode_signal` (sigrok) | protocol-decoder catalog + decode a logic-analyzer capture (I2C/SPI/UART/USB/…) — caller-supplied sigrok-cli |
| pcap | (capinfos) | capture metadata |
| Secrets / IOCs | `secrets`, `iocscan` | credential & indicator scanning |

Plus cross-cutting analysis: `identify` (routes any artifact to the right
reader), `hardening`, `cfg`, `reachability`, `vulnhunt`, `cvelookup` /
`cve_agent`, `patchdiff`, `coredump`.

First-class native static queries (`nativequery.py`, on the shared radare2
session — r2 disassembles, never executes): `analyze_function`,
`get_call_graph`, `find_xrefs_to_name`, `address_name`, `trace_call_path`.
They degrade honestly when radare2/r2pipe is absent.

### 4.1 Evidence ledger — grounded reconstruction with obligations

`ledger.py` is the formal backbone of the "fundamentado" promise: a stateful
**residual-unknown** lifecycle where every open question carries an
*obligation* and can only be closed when the evidence meets it.

- `record_unknown` / `update_unknown` / `list_unknowns` — track open questions
  with a `required_authority` (`static-only` → `controlled-replay` →
  `instrumented` → `live`) and `required_confidence` (`asserted` → `observed`
  → `reproduced` → `verified`), plus recommended probes and optimistic-
  concurrency revisions.
- `record_evidence` — observations carrying their own authority/confidence and
  a sha256 content seal.
- `verify_unknown_resolution` — closes an unknown **only** when it has a
  resolution, ≥1 supporting evidence that meets *both* obligation ladders, and
  no contradicting evidence; otherwise it names the unmet obligation and leaves
  it open. This is the engine refusing to call something resolved on faith.
- `export_evidence_bundle` / `import_evidence_bundle` / `get_evidence_bundle` —
  JSON bundles sealed with a canonical sha256 digest; a tampered bundle is
  rejected on import.

---

## 5. Runtime & external connectors (separate module)

Kept deliberately out of the static grounding core. Caller-supplied,
authorized targets only; all output is untrusted data.

- **Dynamic module** (`dynamic.py`): `dynamic_adb` (device/prop/getprop
  inspection), `dynamic_frida` (instrumentation), `dynamic_browser`
  (Playwright-driven, using the pre-installed Chromium).
- **Process-scenario capture** (`proccapture.py`): `capture_process_scenario`
  runs an authorized target once under a bounded timeout and records its
  observable behaviour (argv, exit, duration bucket, **normalized**
  stdout/stderr, sha256 seal); `compare_process_captures` diffs two captures to
  surface changed behaviour. Normalization (addresses/PIDs/timestamps/temp
  paths) makes deterministic runs compare equal so a real change stands out.
- **Ghidra headless** (`callertools.py`): `ghidra_decompile` locates a
  caller-provided Ghidra headless install and parses its pseudocode.
- **JEB** (`jebconnect.py`): JSON-RPC over HTTP to `BINORACLE_JEB_MCP_URL`.
- **IDA Pro & Hopper** (`nativeconnect.py`): JSON-RPC over HTTP to
  `BINORACLE_IDA_MCP_URL` / `BINORACLE_HOPPER_MCP_URL` — `list`/`call` the
  caller's own IDA/Hopper MCP tools (decompile, xrefs, call graph, search).

---

## 6. Verification status

- **MCP tools:** 73 registered (`binoracle/mcp_server.py`).
- **CLI:** subcommands for every reader and exploit verifier (`binoracle/cli.py`).
- **Tests:** `tests/test_smoke.py` — 125 tests. Execution tests for each
  exploit technique auto-skip via `native_available()` when no sandbox is
  present, so the suite is green on any box and *actually proves the shells*
  where a sandbox exists.
- **Corpus:** `samples/build.sh` builds the full practice corpus as real Linux
  ELFs (gcc:13 Docker image, or a Linux host-gcc fallback), including the
  32-bit and heap samples. `samples/bin` is gitignored.

**How to reproduce the exploit proofs**

```bash
make pwn-image            # build the binoracle-pwn sandbox image (optional; native fallback exists)
bash samples/build.sh     # build the vulnerable corpus
pytest tests/test_smoke.py -v   # execution tests run where a sandbox is available
```

---

## 7. The one rule, restated

If binoracle says **`verified`**, it means the engine *did the thing* —
popped the shell, forged the chunk, hijacked the pointer — in a sandbox and
read back the proof. If it can't, it says so and tells you why. That is the
whole point.
