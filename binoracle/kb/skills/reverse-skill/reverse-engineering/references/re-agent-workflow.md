# RE Agent Workflows (Static ↔ Dynamic)

> Source Inspiration: Binary-Reverse Engineering Phase Division, Community RE Skills (Frida/r2/Ghidra/IDA Loop), Cerberus Triad (Static/Dynamic/Injection)
> Issue #65 Increment: IAT Fixing Iron Law, Six Stage Mapping, Equivalence Paths for .NET/DLL and SYS; User Command Feasibility Gate; Bypass Patches 6-10; Anti-Tampering/Misleading Recipes A-T; Non-PE Formats Recipe U-V (2026-08-12)
> Applicable: `reverse-engineering/`, `ida-reverse/`, `radare2/`, `malware-analysis/`, and CRE Role Handover

## 0. Startup

```text
- scope.md: offline sample path or authorized device/target machine
- tool-index: file/strings/r2/ida/frida etc actual paths
- role: cre (ops/role-map)
```

## 0.1 Transition Handoff (Decision Delta)

Between stages, no re-injection of a complete case context. `scope.md`, `workitems.md`, and Evidence remain authoritative; only the transition delta is carried in `timeline.md`:

1. Write only the `decision_delta` that truly affects subsequent actions at stage/turn end; write `[]` for unchanged routes/authors/scope/network profiles/tool states/hypotheses.
2. Only carry forward references (`carry_forward_refs`) for unchanged route/authors/scope/network profiles/tool states/hypotheses, and consumers read from these references without re-serializing or emitting.
3. The `decision_delta` is not a complete state; the consumer must inherit the references first before applying the delta.
4. Only when two or more evidence-supported branches lead to different next actions will we stop at the next-step menu; deterministic gates are directly advanced.

Example: Triage completed and the only valid next action is Static, then the transition would be `decision_delta: [phase=triage->static]` + `carry_forward_refs: [scope.md, evidence/E-triage.md]`.

## 0.5 User Command Feasibility Gate (Issue #65)

**Principle**: Obey user **goals**, not their **step order**. Explain the prerequisite before skipping steps and confirm; mandatory steps after confirmation must be followed and truthfully annotated with Evidence quality.

| Situation | Agent MUST |
|------------|-------------|
| User wants X, and current state can yield valid Evidence | Execute X and update Evidence |
| User wants X, but there is a known blocking prerequisite (e.g., shellcode detected and static IAT un-readable) | **Prohibit** pretending to complete meaningful IAT; ① Clearly explain the blockage; ② Provide recommended order (start deobfuscating/fixing IAT or directly dynamic API capture); ③ Ask user if they want "still force look at current table" or "follow recommendation" |
| User explicitly **forces** a current step (e.g., must still check IAT even without deobfuscation) | Execute and record Evidence, MUST mark `quality=unreadable` / `packed` (or equivalent); **Prohibit** drawing conclusions like "no network capability" based on this forced step |
| User accepts the recommended order | Do prerequisite steps first; complete X automatically or upon request; **Prohibit** using prerequisite steps (like deobfuscation) to pretend "import table check" is done |

**Relationship with "redo X"**: Redoing X = redoing the named step (or its confirmed legitimate prerequisite negotiation result), prohibit substituting unrelated steps. De-obfuscating is a **prerequisite** for import tables, not an alternative.

Typical conflict: User says on shellcode sample "skip deobfuscation and look at import table first" → Shellcode often alters import directories or encrypts descriptors; static table is bloated with no meaning → Follow the "known blocking prerequisite" row, do not silently de-obfuscate to pretend, nor hand over a bloated table as completion.

## Triage (5–15 Minutes · Mandatory Starting Point)

```text
- Calculate sample hash (MD5/SHA256) → Unique ID
- Identify file type: EXE / DLL / SYS / ELF / Mach-O / .NET / Script (bat/ps1/vba) / JS / APK, etc.
- Non-PE/Script/APK/Driver-specific: See §3.4 and `references/nonpe-format-cookbook.md` (U–AV)
- File / DIE / Entropy / Shell characteristics (PEiD / DIE / Exeinfo, etc.)
- Architecture: x86 / x64 / ARM; Compilation language clues (VC++ / Delphi / .NET / Go / Rust)
- Packing type clues: UPX / ASPack / VMProtect / Themida / Unknown obfuscation
- Strings / rabin2 -z for leaks
- MUST import/export anchors (see below "Import Table Hard Loops and Equivalent Paths") if not PE/Script/APK/Driver-specific; If user is bypassing shell, proceed to §0.5 first.
- Output: E-triage (MUST include imports or equivalent anchor summary with quality annotation where applicable) + Hypothesis list
```

**Transition Gates (Triage → Static/Dynamic)**: Before recording imports in E-triage and summarizing them **or** if there are no valid equivalent anchors, MUST NOT proceed to Dynamic analysis unless IAT repair failures have been recorded and a dynamic bypass is chosen (see §1.2), and MUST NOT claim "Basic triage completed." If parsing fails, the failure output must be written into Evidence; do not skip it. When users request "redo import table check," they MUST redo the imports/export steps themselves (or complete §0.5 under a pre-condition after negotiation) and MUST NOT switch to other analysis steps as a cover.

### 1.1 Import Table Hard Loops and Equivalent Paths

| Sample Type | MUST Anchor Point (Evidence) | Description |
|-------------|---------------------------------|--------------|
| Native PE/ELF/Mach-O (IAT readable) | `E-imports` / `E-triage-imports`: Summary of import categorization | `rabin2 -i` / IDA imports / Equivalent |
| DLL / SYS / Shared Library | **Parallel** `E-imports` + `E-exports` (`rabin2 -i` + `rabin2 -E`) | Export table priority is equivalent to the import table (external entry points) |
| .NET Managed (no traditional IAT) | **Equivalent Path**: dnSpy/IL/Metadata/Assembly References and sensitive API summaries → Still write into `E-imports` or `E-triage-imports` semantic slots | **Prohibited** from declaring a "hard loop" due to lack of IAT; dnSpy inspection = native "import table check" |
| Import Table Parsing Failure / Empty / Packed with obfuscation | Record failure or obfuscated output as Evidence and mark `quality` | Do not silently skip it; Obfuscated data cannot support the conclusion that capabilities are negated |

**Warning on Clean Import Tables (MUST remind)**: If the import table is "too clean" (only basic DLLs like kernel32/ntdll, almost no business APIs), highly suspect dynamic loading via `LoadLibrary` + `GetProcAddress`; Note it in Evidence and **SHOULD** transition to Dynamic analysis for capturing memory API; Do not claim "no network/file capabilities" based solely on static IAT.

**High-Risk API Combinations (Patch 8 · SHOULD)**: When the import table is excessively long, prioritize outputting clusters of malicious combinations. Filter out pure system calls. Example (not exhaustive):

- High-risk cluster: `FindWindowA/W` + `WriteProcessMemory` + `CreateRemoteThread` (injection)
- High-risk cluster: `CryptEncrypt` / `CryptAcquireContext` + numerous `FindFirstFile` / `DeleteFile` (ransomware tendency)
- High-risk cluster: `InternetOpen` / `WinHttp` / `URLDownloadToFile` + persistent API (`RegSetValue` / `CreateService`)
- Singletons like `CreateFile` / `ReadFile`, etc., are mostly benign noise unless they coexist with the above clusters

### 1.2 Deobfuscation and IAT Handling (High-Risk Branch · Issue #65)

```text
Branch A: No shell / .NET Managed
  → Directly proceed to §2 Static (Managed .NET uses equivalent anchors)


Branch B: Encapsulated / Strong Fuzzing  
Step 1: Attempt De-Encapsulation (Automatic Decapsulation Machine / Manual OEP Discovery) - Must be in authorized and isolated environment  
Step 2: Attempt IAT Repair  
Tool: x86 → ImportREC (or equivalent); x64 → Scylla (or equivalent). Avoid using ImportREC for 64-bit samples.  
Case B1: IAT Repair Successful and Resolvable → Record E-imports (post-repair) → §2 Static  
Case B2: ImportREC/Scylla reports error, repair fails to run, or IAT is completely scrambled (VMP/encrypted shell)  
→ **IAT Repair Iron Law**: Immediately stop attempting static IAT repair  
→ MUST record E-iat-repair-fail (command, tool, failure phenomenon, decide to switch to dynamic)  
→ Directly enter §3 Dynamic: API breakpoints / Hardware execution breakpoints / Memory search for imports  
→ This is not considered "skipping the import table": The path of the import table has been attempted and recorded as evidence  
Case B3 (Patch 6): De-encapsulation and IAT repair result in double-click crash or blue screen (suspected file CRC/self-check)  
→ Abandon static repair attempt; record E-self-check-crash or combine with E-iat-repair-fail  
→ Enter §3 Dynamic: Set breakpoints on CreateFile / GetFileSize / Hash-related APIs to locate the bypass point  

**IAT Repair Iron Law (MUST)**: Prioritize automatic/half-automatic repair attempts. Once a repair tool reports an error or the repaired program cannot run, **immediately stop** attempting static IAT repair and switch to dynamic debugging using API breakpoints (e.g., `bp CreateFile` / key network APIs) to capture import functions during runtime.

## Static (Foundation Static Anchors → Deep Dive)

| Tool | When |
|------|------|
| radare2 / rabin2 | Quick functions/imports/strings (imports must be completed or marked as bypassed in Triage MUST) |
| IDA / Ghidra (MCP or headless) | Deep dive, cross-references, types; review imports classification during survey phase |
| jadx / dnSpy | Android / .NET |
| OLLVM Documentation | Control flow flattening suspicion |

```text
- Confirm E-imports/E-triage contains import table or equivalent anchor points Evidence (missing then fix first, do not post-process)
- If DLL/SYS: confirm E-exports are recorded
- Group sensitive APIs and cluster high-risk combinations (patch 8)
- Hardcoded domain/IP/URL strings; is the payload hidden in resource sections?
- Pin down key functions (encryption/validation/network/auth) → Address/symbol write Evidence
- One path fails → Switch tool (IDA↔r2↔Ghidra)
- Timebox (patch 9 · SHOULD default): Static deep dive takes no more than 15 minutes and still no critical paths → Force transfer to §3 Dynamic (user/task can cover duration)
```

**Without MCP**: Use exported text decompiled for further analysis (compare with P4nda0s reverse skills / IDA-NO-MCP approach), still write Evidence path.

## 3. Dynamic (Cross-Validation Loop)

Core Concept: **Static provides clues → Dynamic validation → Validation stuck → Static re-review**

### 3.0 Breakpoints Primer (Patch 7 + 10 · MUST Order)

Before starting the sample with a user-mode debugger (such as x64dbg, etc.), pre-set breakpoints in accordance with the "fourth level rocket" (the order may vary based on architecture/tool names):

1. **TLS Callback** breakpoint (may have already run before)
2. **Entry Point EP** breakpoint
3. **Sensitive API** breakpoints (e.g., `CreateRemoteThread`, network, file write)
4. **Fallback**: `ExitProcess` / process exit path breakpoint (patch 10) — If the sample exits due to anti-debugging directly, do not immediately restart; dump memory and record the pre-crash image path in Evidence for string/data recovery.

```text
- Frida / x64dbg / gdb / emulator: Validate static assumptions
- Run after setting breakpoints as per §3.0; single-step tracking of stack/registers (white-box)
- Behavioral monitoring: Sandbox / Procmon / RegShot (black-box)
- IAT repair failure / self-checking crash sample: Hardware breakpoint or memory search to capture APIs like `CreateFile`/`GetFileSize`, check CRC
- Anti-debugging / anti-Frida → reverse-engineering / anti-analysis
- Android: Root detection / SSL pinning bypass script generated on demand, **must be on authorized device**
- Crash logs drive the next hook (adaptive loop)
- Time Box (patch 9 · SHOULD default): Single-step tracking of about 200 instructions without malicious behavior clues → Force return to static for string/anchor-point re-mapping (can overwrite)
```

### 3.1 Sandbox / Dynamic No-Action Emergency Branch (MUST)

```text
No action or immediate exit / indefinite sleep
  → Check anti-debugging / virtual machine routines (CPUID, high-precision timing, sandbox features, etc.)
  → Attempt hardware breakpoint bypasses, point patching, or switch to a physical machine/higher fidelity environment
  → Write "no-action + suspected anti-VM" in Evidence and do not label as "sample harmless" without conditions
```

### 3.2 Time Box Strategy (Patch 9 · SHOULD)

| Phase | Default Threshold (user/task override allowed) | Action |
|------|----------------------------------------------|--------|
| Static deep dive with no critical paths | ~15 minutes | Enter Dynamic |
| Dynamic single-step with no progress | ~200 instructions | Return to Static for string/inter-reference re-mapping |
| Any path repeats failure | Record Evidence and switch tools or bypass | Prohibit empty loops of the same failed method |

### 3.3 Anti-Debugging / Obfuscation Bypass Quick Reference (Issue #65 Patch A–T · Frequent)

For complete index and action details, see `reverse-engineering/anti-analysis.md` "Agent Response Recipe A–T". Here only list **P0 must check + common transitions**. Default to authorized isolation lab; patching/re-setting flags is not an unauthorized production action.

```text
- Frida / x64dbg / gdb / emulator: Validate static assumptions
- Run after setting breakpoints as per §3.0; single-step tracking of stack/registers (white-box)
- Behavioral monitoring: Sandbox / Procmon / RegShot (black-box)
- IAT repair failure / self-checking crash sample: Hardware breakpoint or memory search to capture APIs like `CreateFile`/`GetFileSize`, check CRC
- Anti-debugging / anti-Frida → reverse-engineering / anti-analysis
- Android: Root detection / SSL pinning bypass script generated on demand, **must be on authorized device**
- Crash logs drive the next hook (adaptive loop)
- Time Box (patch 9 · SHOULD default): Single-step tracking of about 200 instructions without malicious behavior clues → Force return to static for string/anchor-point re-mapping (can overwrite)
```

| Trigger Feature | Preferred Action (Summary) | Evidence |
| ----------------- | ---------------------------- | ---------- |
| `cpuid` 后 jz/jnz (A) | Lab: Modify flags or patch to real branches; record address of detection points | `E-anti-debug-cpuid` |
| `rdtsc` + sub/cmp (B) | bp rdtsc or hook time source; prevent indefinite spin loops etc. sandbox timeouts as benign | `E-anti-debug-rdtsc` |
| PEB BeingDebugged / NtGlobalFlag (K) | ScyllaHide or hand-edit PEB; patch conditional jumps | `E-anti-debug-peb` |
| `NtQueryInformationProcess` DebugPort/Flags/Object (P) | ScyllaHide / hook return value; record class parameter | `E-anti-debug-ntqip` |
| Few but rich imports → API hash (N) | bp GetProcAddress; hash reverse to IDA | `E-api-hash` |
| Strings empty but have network/file behavior → String encryption (I) | Find decode routines xref; decrypt and dump back | `E-string-decrypt` |
| Signed but suspicious source (F) | SigCheck: valid/cancelled/timeout; **invalid do not downgrade** threat level | `E-sig-forge` |
| Standard strings with no IOC → Wide character test (T) | Use `strings -el` / UTF-16LE; Alt+A unicode | `E-wide-strings` |
| Debugger name string/toolhelp scan (C) | bp CreateToolhelp32Snapshot link | `E-anti-debug-procscan` |
| AddVectoredExceptionHandler + intentional exception (D) | bp VEH register; analyze handler | `E-anti-debug-veh` |
| int3 / DR0–DR7 (M) | patch int3; soft breakpoints or ScyllaHide hide hardware BP | `E-anti-debug-bp` |
| Multiple PE headers/overlapping sections (G) | Map real section tables + entropy; don't trust section names | `E-pe-anomaly` |
| File end > section sum Overlay (J) | Extract overlay; file/entropy; find load offset xref | `E-overlay` |
| .rsrc abnormal large/high entropy RT_RCDATA (Q) | Extract resources; FindResource chain + decrypt dump | `E-rsrc-payload` |
| Runtime-only DLL loading (R) | Check Delay Import; bp delay-load helper | `E-delay-import` |
| While+switch star CFG (H) | See `ollvm-deobfuscation.md`; plugin fails then dynamic path | `E-cff` |
| True/false always branches (S) | See ollvm / symbolic execution; dynamic as is | `E-opaque-pred` |
| `/proc/self/status` TracerPid (L) | **Linux/ELF**; hook or patch; Windows main path not mandatory | `E-anti-debug-tracerpid` |

**Constraints**: Record Evidence even if bypass fails; do not write "sample benign" for "debugging trigger exit". See anti-analysis cookbook section for complete A–T and P2 (compile time, O instructions).

### 3.4 Non-Pe/Multi-format Bypasses (Issue #65 Patch U–AV · Routing)

Complete Index: `reverse-engineering/references/nonpe-format-cookbook.md`. Here only list **type → entry**; detailed actions in cookbook / corresponding skill.

| Type | Jump to | P0 Evidence Anchor (Example) |
|------|--------|---------------------------------|
| BAT/CMD | cookbook §1 + malware | `E-batch-deobf` |
| PowerShell | cookbook §2 + malware | `E-ps-decode-layer-N` |
| VBA Macro | cookbook §3 + malware | `E-vba-pcode` |
| Strong-obfuscated JS / JSVMP | **js-reverse** + cookbook §4 | `E-js-vmp` / `E-js-deobf` |
| Kernel Driver | kernel-driver-reverse + cookbook §5 | `E-driver-irp-handlers` / `E-driver-ioctl` |
| DLL-side focus | cookbook §6 (AM≡A–T **R**) | `E-dll-tls-dllmain` / `E-exports` |
| Android Format/Hidden Icon | **apk-reverse** + cookbook §7–8 | `E-android-wiper-*` / `E-android-hidden-icon-*` |

**Constraints**: No separate "Non PE six stages"; split with §3.3 A–T (PE anti-debug vs multi-formats). Authorized lab; format/BIOD/reflection = detection/investigation statement.

## 5. Six Phases Practical Mapping (Issue #65 Mind Map → This Document)

| Phase | Chapter in This Document | Hard Rules |
|----------|-----------------------------|--------------|
| 1 Preliminary Quick Assessment | §0–§1 Triage | Hash, architecture, file type, PE check; imports/anchor points; §0.5 Instruction Gates |
| 2 Deobfuscation and IAT | §1.2 | IAT hard rule; failure/self-checking crash → Evidence → Dynamic |
| 3 Foundation Static Anchors | §2 Static | High-risk API combinations; time-box SHOULD |
| 4 Deep Cross-Validation | §3 Dynamic | Breakpoints rocket science; emergency for no behavior; time-boxes; §3.3 A–T; §3.4 U–AV type routing |
| 5 Extraction of IOC and Attack Chain | §4 Synthesis | IOC + Kill Chain / Path |
| 6 Archiving and Normalization | §4 + docs-generator / YARA | Structured report; rule selection available |

## 6. Differences with "Heap RE Skill Plugin"

- This package uses **phase gates + tool-index**, does not default to enabling Hex-Rays' "unsafe fully automatic execution" type plugins  
- Dynamic instrumentation defaults to **offline/lab network profile**  
- IAT/Import Table: **try and record** takes precedence over "infinite static brute force" or "silent skip"  
- User commands: **target priority + premise negotiation**, prohibits using irrelevant steps to impersonate named steps