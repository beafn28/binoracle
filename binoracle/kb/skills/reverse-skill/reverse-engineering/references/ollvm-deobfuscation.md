# OLLVM 反混淆 / Obfuscator-LLVM Deobfuscation

> A workflow for deobfuscating APK .so, ELF binaries, and control flow flattened scenarios.
> Tools and variant information are based on community active project research in 2026, not from training memory.
> Suitable for: Android NDK hardening, CTF reverse engineering, shellcode analysis, commercial obfuscator resistance.

---

## 0. Quick Decision: Which Tool Should I Use?

Based on your environment and judgment of the target obfuscation type, choose accordingly:

| Your Situation | Preferred Tool | Alternative | Description |
|--------------|----------------|-------------|-------------|
| Have IDA Pro 7.5-7.7 + Hex-Rays, want to flatten in one click | **obpo-plugin** | d810-ng | obpo uses microcode + data flow + hybrid execution, best effect, but cloud plugin (needs internet, core closed source) |
| Have IDA Pro (any newer version), want local one-stop deobfuscation | **d810-ng** | D-810 Original Version | Local, open-source, integrates Z3, supports multiple variants including OLLVM/Tigress/Hodur/Approov |
| Have Binary Ninja | **ollvm-breaker** | — | Targeted for Android .so (e.g., libvdog samples) |
| No IDA/BN, pure script, target x86/x64 | **ollvm-unflattener** (Miasm) | angr deflat | Based on Miasm symbolic execution, BFS multi-layer processing |
| No IDA/BN, pure script, target x86/x64 | **ollvm-unflattener** (Miasm) | angr deflat | Based on Miasm symbolic execution, BFS multi-layer processing |
| Pure Python symbolic execution, CTF scenario | **angr** Deobfuscator | Triton | GUI-independent, scriptable |
| Target is ARM64 .so, no IDA | **deollvm** (Unicorn) | angr | Based on Unicorn ARM64 deflat |
| Encountering BR obfuscation (indirect branches) | **DeObfBR** | Set data segment to read-only | Goron/Arkari style BR obfuscation can be simply resisted with a read-only data segment |
| Encountering Tigress obfuscation | d810-ng `UnflattenerSwitchCase`/`UnflattenerTigressIndirect` | — | d810-ng includes a specialized unflattener for Tigress |

> **Core Recommendation:** Prioritize using **d810-ng** (local, actively maintained, wide variant coverage). When cloud services are available, **obpo-plugin** performs best. Use **angr/Miasm** symbolic execution for customization if both fail.

---

## 1. Modern OLLVM Variants Ecosystem (2026 Community Survey)

OLLVM is no longer just the original repository from 2017. Below are the currently active obfuscator branches, **it must first be determined which variant the target belongs to** because the countermeasures vary greatly between different variants:

### 1.1 Obfuscator Branch Family Tree

| Variant | Base LLVM | New Features Compared to Original OLLVM | Countermeasure Focus |
|---------|-----------|------------------------------------------|----------------------|
| **Obfuscator** (Original) | 3.3~4.0 | sub + bcf + fla (three foundational passes) | Standard tools can handle them |
| **Hikari** | 6~8 | Anti Class Dump, Function Call Obfuscate, Function Wrapper, Indirect Branching, Split BB, String Encryption | Decrypt strings first + fix indirect jumps |
| **Hikari-LLVM15** | 15~19 | + Anti Debugging, Anti Hook, Constant Encryption | Closed source; Constant Encryption increases static analysis difficulty |
| **goron** | 7~10 | Indirect Branch/Call/GlobalVariable | ⚠️ Goron-style indirect obfuscation can be easily countered by setting the data segment to read-only |
| **Arkari** (komimoe/Hikari) | 14~latest | Based on goron, continuously maintained | Similar to goron; data segment only readable partially counters it |
| **Pluto** | 14 | MBA Obfuscation, Random CF, Split BB, **Trap Angr** (specifically for angr) | ⚠️ Trap Angr pass makes angr symbolic execution ineffective; switch tools or bypass the trap |
| **Polaris** (Original Pluto) | 16 | Alias Access, Indirect Branch/Call, String Encryption, Merge Function, Linear MBA, Dirty Bytes Insertion, Function Splitting, Junk Insertion | Combines Hikari+Pluto, most challenging; requires layer-by-layer handling |
| **O-MVLL** | open-obfuscator | Python-driven pass manager; Anti Hooking, Arithmetic(MBA), BB Duplicate, CF Breaking, Function Outline, Indirect Branch/Call, Opaque Constants | Commonly used for modern Android hardening; easy customization with Python configuration |
| **amice** (Rust) | Rust implementation | Full suite + VM Flatten, Instruction Virtualization, Delayed Offset Loading, Parameter Aggregation | Includes VMization; requires VM handler restoration rather than simple deflat |
| **VMP Family** (SmallVmp/VMPilot/xVMP/VMPacker) | — | Instruction virtualization | **Not within the OLLVM scope**, requires VM reverse engineering; refer to VM-specific tools |

### 1.2 Key Indicators for Determination

- **Trap Angr** (Pluto/Polaris): If angr crashes or paths explode while running, suspect the target used a Trap Angr pass → Switch to d810-ng or Unicorn dynamic methods
- **Goron/Arkari indirect jumps**: If the distributor uses indirect jumps (BR x8 instead of switch), first try setting the relevant data segment to read-only; indirect jump targets often become statically solvable
- **Constant Encryption** (Hikari-LLVM15/Polaris/O-MVLL): Constants are decrypted at runtime, pure static analysis cannot see real values → Need Unicorn dynamic execution of decryption stubs
- **VM Flatten** (amice): Control flow becomes VM dispatch loop, **do not treat it as a regular fla**; need to first identify the VM handler table

## 2. OLLVM Obfuscation Type Detection

OLLVM's three core pass recognition features:

### 2.1 Control Flow Flattening (Control Flow Flattening / `fla`)

**IDA View Features:**
- Function entry jumps to a unique dispatcher block.
- Main logic is split into multiple basic blocks, each ending with a jump back to the dispatcher.
- The dispatcher decides the next block to execute using a **state variable**.
- A large `switch` structure with no logical connection between cases.

```
Original:             OLLVM flattened:
  block_A               entry -> dispatcher
  block_B                 ↓
  block_C              state_machine:
                         switch(state):
                           0 → block_A
                           1 → block_B
                           2 → block_C
```

**Variants (d810-ng recognizes multiple types of dispatchers):**
- O-LLVM: `switch / if-chain` + state variable
- Tigress: `m_jtbl` (switch-case) or `m_ijmp` (indirect jump, requires `goto_table_info` configuration)
- Hodur (PlugX): Nested `while(1)` state machine, `jnz state, #CONST`, **no switch dispatcher**
- Approov: `while(v8 != C)`, constant states concentrated in `0xF6000–0xF6FFF`

### 2.2 Bogus Control Flow (Bogus Control Flow / `bcf`)

- Insert **unreachable fake branches** between each real branch.
- Fake branches protected by **opaque predicates** (always true/false, but static analysis cannot directly prove).
- Large amounts of dead code bloat the function size.

```c
// Classic opaque predicate: x(x+1) must be even, compiler cannot prove it
if (x * (x + 1) % 2 == 0) {
    // Real logic
} else {
    // Unreachable garbage code
}
```

### 2.3 Instruction Substitution (Instruction Substitution / `sub`) → MBA

- Simple arithmetic/bit operations replaced with equivalent complex expressions (MBA, Mixed Boolean-Arithmetic)

```
a + b  →  (a ^ b) + 2*(a & b)
a ^ b  →  (a | b) - (a & b)
a - b  →  a + (~b) + 1
```

### 2.4 Fast Classification Table

| Obfuscation Type | IDA Feature | Main Antidote |
|------------------|-------------|---------------|
| fla (flattening) | Large switch + dispatcher | obpo / d810-ng / deflat |
| bcf (fake control flow) | Unreachable branches + dead code | d810-ng opaque predicate removal / symbolic execution |
| sub/MBA | Complex arithmetic expressions | d810-ng MBA simplifier / SiMBA (Z3) |
| fla + bcf + sub | Full, extremely bloated | **Layered deobfuscation (first bcf, then fla, then sub)** |

---

## 3. Detailed Analysis of Mainstream Tools (Active Community Projects)

### 3.1 obpo-plugin — Strongest Effect, Cloud Plugin

> [obpo-project/obpo-plugin](https://github.com/obpo-project/obpo-plugin) · 629⭐ · 2026-06 Active

A pseudocode optimizer based on Hex-Rays **microcode**, using **data flow tracking + program slicing + hybrid execution (concolic)** to reconstruct flattened control flow. It is one of the strongest effects recognized by the community.

**Key Features:**
- Operates at the microcode layer, directly optimizing decompiled output (not changing ASM)
- Supports IDA 7.5.0 / 7.6.0 / 7.7.0 + Hex-Rays
- Architectures: ARM, ARM64, x86, x86_64, PowerPC, PowerPC64, MIPS (7.6/7.5)
- **Cloud Plugin**: Target function binaries are uploaded to obpo-server for processing (core closed-source, plugin free open-source)
- Server is self-hosted and paid maintenance, timeout 600s, **prohibited multi-threading/malicious calls**

**Installation and Usage:**
```text
1. Download obpo_plugin.py and obpoplugin directory
2. Copy to IDA plugins path
3. Restart IDA, open target binary
4. In CFG, locate the dispatcher block (usually looks like this):
   [Screenshot reference in repository assets/dispatchblock.png]
5. Right-click → OBPO → Mark and process function
6. After processing, refresh decompiler
7. Continue marking new dispatcher blocks based on decompilation changes (iterative handling of nested fla)
```

**Applicable Scenarios and Limitations:**
- ✅ Standard and nested fla, good effect
- ⚠️ Requires internet connection, sensitive samples (internal undisclosed vulnerabilities, commercial secrets) use with caution — binaries will be uploaded
- ⚠️ Server may go down, depends on author maintenance
- ❌ Cannot solve all obfuscations (author explicitly states)

### 3.2 d810-ng — Local One-Stop Choice

> [w00tzenheimer/d810-ng](https://github.com/w00tzenheimer/d810-ng) · 223⭐ · Updated on 2026-06-26

The modern maintenance/rewrite version of D-810 (Next Generation). Runs locally, open-source, integrates **Z3 SMT** solver, covers the widest variety of obfuscations.

**Core Capabilities (Organized by d810-ng README):**

*Instruction-Level Optimizations:*
| Category | Description |
|----------|-------------|
| MBA simplification | `(a+b)-2*(a&b) => a^b`, Z3-verified DSL rules |
| Hacker's Delight | Bitwise equivalence (from the book "Hacker's Delight") |
| O-LLVM patterns | MBA patterns specific to Obfuscator-LLVM |
| Constant folding | 22 constant simplification rules |
| Predicate simplification | Transparent predicate removal (setz/setnz/lnot/smod) |
| Z3 rules | Use SMT solver when template matching fails |
| Hodur-specific | MBA patterns for PlugX (Hodur) malware |

*Control Flow Unflattener (By Target Obfuscation Type):*
| Unflattener | Target | Description |
|------------|------|-------------|
| `Unflattener` | O-LLVM | Standard switch/if-chain + state variables |
| `UnflattenerSwitchCase` | Tigress | Tigress switch-case dispatch (`m_jtbl`) |
| `UnflattenerTigressIndirect` | Tigress | Tigress indirect jump (`m_ijmp`), requires `goto_table_info` configuration |
| `HodurUnflattener` | Hodur (PlugX) | Nested `while(1)` + `jnz state, #CONST`, no switch |
| `BadWhileLoop` | Approov | `while(v8 != C)`, constant state in 0xF6000–0xF6FFF |
| `UnflattenerFakeJump` | General | Remove always-true/false conditional jumps |
| `SingleIterationLoopUnflattener` | Residual | Clean up single iteration loops where `INIT == CHECK` and `UPDATE != CHECK` |
| `UnflattenControlFlowRule` (Experimental) | General | CFG unflattener based on path emulation |

**Installation and Usage:**
```text
1. Clone d810-ng
2. Install dependencies (including Z3)
3. Copy to IDA plugins directory
4. Load plugin in IDA with Ctrl-Shift-D
5. Check the rule set to apply in the GUI
6. Apply to target function
```

**Why Choose d810-ng Over Original D-810:**
- The original D-810 is less maintained
- d810-ng has CI testing, refactored code, and new unflattener for Tigress/Hodur/Approov
- Integrated with Z3, falling back to SMT solving when template matching fails, higher success rate

### 3.3 ollvm-unflattener — Miasm Symbolic Execution, Pure Script

> [cdong1012/ollvm-unflattener](https://github.com/cdong1012/ollvm-unflattener) · 265⭐ · 2026-06 活跃

Based on the **Miasm** symbolic execution engine, without relying on IDA/BN, purely Python command-line.

**Features:**
- Uses Miasm symbolic execution to recover original control flow (distinguishing from MODeflattener's pure static method)
- **BFS Multi-layer Processing**: Automatically follows target function calls, recursively deobfuscating
- Supports Windows/Linux x86/x64
- Outputs the new binary after deobfuscation

**Installation and Usage:**
```bash
git clone https://github.com/cdong1012/ollvm-unflattener.git
cd ollvm-unflattener
pip install -r requirements.txt   # miasm, graphviz, keystone-engine

# Basic usage
python unflattener -i <input.bin> -o <output.bin> -t <function_addr> -a
# -a: Automatically follow calls for multi-layer processing
```

**Applicable to:** No IDA, target x86/x64, batch script processing required.

### 3.4 ollvm-breaker — Binary Ninja 实战

> [amimo/ollvm-breaker](https://github.com/amimo/ollvm-breaker) · 441⭐

Uses **Binary Ninja** to de-flatten binaries, with the repository自带 Android 加固样本 `libvdog.so` as a test case, fixing functions like JNI_OnLoad, crazy::GetPackageName, and prevent_attach_one.

**Applicable to:** Binary Ninja users, Android .so实战.

### 3.5 deollvm — ARM64 Unicorn

> [GeT1t/deollvm](https://github.com/GeT1t/deollvm) · 34⭐ · 2026-04

Based on **Unicorn** for ARM64 OLLVM deflattening. A backup option when no IDA is available.

### 3.6 DeObfBR — BR 混淆专项

> [Mrack/DeObfBR](https://github.com/Mrack/DeObfBR) · 96⭐ · 2026-06-25

Specialized in removing **BR 混淆** (indirect branch obfuscation, Goron/Arkari style).

**⚠️ Simple countermeasure technique (from awesome-ollvm):** For indirect related obfuscation in the Goron/Arkari style, you can simply set the data segment to read-only—indirect jumps depend on writable data segments at runtime. Setting it to read-only makes it statically solvable.

### 3.7 angr — 符号执行通用框架

```python
import angr

proj = angr.Project("target.so", auto_load_libs=False)
cfg = proj.analyses.CFGFast()
func = proj.kb.functions[0x12345]

# Built-in Deobfuscator
deob = proj.analyses.Deobfuscator(func=func)
deob.normalize()
```

**⚠️ Pluto/Polaris 的 Trap Angr pass:** These variants specifically wrote traps to trick angr's symbolic execution. If angr experiences path explosion or exceptions, suspect the target used Trap Angr → switch to d810-ng or Unicorn dynamic methods.

---

## 4. Full Decryption Workflow (By Scenario)

### 4.1 General Decision Tree

```
Target binary
  ↓
1. Identify OLLVM variant (see clues in section 1.2)
  ├── Original OLLVM / Hikari / O-MVLL  → Standard fla/bcf/sub
  ├── Pluto / Polaris                → Be cautious of Trap Angr, avoid angr
  ├── Goron / Arkari                 → Try data segment read-only first, then handle BR
  ├── Tigress                        → d810-ng Tigress unflattener
  ├── Hodur (PlugX)                  → d810-ng HodurUnflattener
  └── amice (contains VM)              → Not purely fla, need VM handler to restore
  ↓
2. Select tool (see decision table in section 0)
  ├── Has IDA + online + non-sensitive sample → obpo-plugin
  ├── Has IDA + local                  → d810-ng
  ├── Has Binary Ninja                 → ollvm-breaker
  ├── No GUI + x86/x64                → ollvm-unflattener (Miasm)
  ├── No GUI + ARM64                   → deollvm (Unicorn) / angr
  └── Pure symbolic execution / CTF    → angr
  ↓
3. Layered Decryption (order is important)
  a) Remove opaque predicates first (bcf)   → d810-ng opaque predicate removal
  b) Then remove control flow flattening (fla) → unflattener
  c) Finally simplify MBA (sub)       → d810-ng MBA simplifier / SiMBA
  ↓
4. Validation
  ├── Function size significantly reduced?
  ├── CFG changes from star/radiating to linear/tree?
  └── Verify logic correctness of key functions with Frida hook?
```

### 4.2 Android NDK .so Decryption Specialization

Android NDK-compiled .so files being obfuscated by OLLVM is the most common scenario for APK reverse engineering.

**Step 1 — Extract .so:**
```bash
adb pull /data/app/~~/lib/arm64/libnative.so
# Or directly extract from APK: unzip target.apk -d out/ ; find out -name "*.so"
```

**Step 2 — Identify OLLVM and variants:**
```bash
readelf -a libnative.so | grep -E "Size|text"   # .text unusually large but few functions → Likely OLLVM
# Open in IDA to examine function features:
#   Large switch → fla
#   Unreachable branches → bcf
#   Complex arithmetic → sub/MBA
#   Indirect jumps BR x8 → Goron/Arkari, try data segment read-only
#   while(1) + jnz state → Hodur, use d810-ng HodurUnflattener
```

**Step 3 — Decryption (layered):**
```
a) bcf: d810-ng opaque predicate removal  (or obpo automatic handling)
b) fla: d810-ng Unflattener / obpo-plugin / deollvm(ARM64)
c) sub: d810-ng MBA simplifier
```

**Step 4 — Dynamic validation with Frida:**
```javascript
// Trace OLLVM state variables to assist deflat in determining state variable addresses
const target = Module.findBaseAddress("libnative.so");
console.log("[+] libnative.so @", target);

// Hook at dispatcher entry to observe state change sequence
Interceptor.attach(target.add(0x1234), {  // dispatcher offset
    onEnter(args) {
        // Read state variable (register/stack position needs to be determined from disassembly)
        console.log("[state]", this.context.x8);  // Assuming state is in x8
    }
});
```

### 4.3 CTF Scenario Quick Decryption

CTFs are usually time-sensitive, so prioritize the fastest path:

```python
#!/usr/bin/env python3
"""CTF OLLVM quick deflat with angr"""
import angr

proj = angr.Project("challenge", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

```

# Find the largest few functions (most likely obfuscated)
funcs = sorted(cfg.functions.values(), key=lambda f: f.size, reverse=True)[:5]
for func in funcs:
    print(f"[*] {func.name} @ {hex(func.addr)} size={hex(func.size)}")
    try:
        deob = proj.analyses.Deobfuscator(func=func)
        deob.normalize()
        print(f"    [+] deobfuscated")
    except Exception as e:
        print(f"    [-] failed: {e}")
        # angr failed → suspect Trap Angr → switch to d810-ng / Unicorn

## 5. MBA Expression Simplification

### 5.1 Common OLLVM MBA Patterns

```python
# These equations are the targets for expression simplification by the OLLVM sub pass
"(a | b) + (a & b)"        # → a + b
"(a | b) - (a & b)"        # → a ^ b
"(a ^ b) + 2*(a & b)"      # → a + b
"(a | b) & ~(a & b)"       # → a ^ b
"~(~a & ~b)"               # → a | b (De Morgan)
```

### 5.2 Tool Selection

| Tool | Method | Applicability |
|------|--------|-------------|
| **d810-ng MBA simplifier** | Batch in IDA, Z3 verification | Preferred, integrated into the decompilation process |
| **SiMBA** (`pip install simba-simplifier`) | Command-line/library | Pure expression simplification, batch processing |
| **Arybo** | Symbolic bit vectors | Large number of MBA expressions |
| **Z3 direct solving** | SMT | Most generic, when template matching fails |

```python
# SiMBA Example
from simba import simplify_mba
exprs = ["(a | b) + (a & b)", "(a ^ b) + 2*(a & b)"]
for e in exprs:
    print(f"{e}  →  {simplify_mba(e)}")
```

---

## 6. Full Decryption Case Script

```bash
#!/bin/bash
# OLLVM deobfuscation pipeline (2026 community tools)
# Suitable for standard OLLVM / Hikari / O-MVLL protected ELF/.so files

BINARY=$1

echo "[*] Stage 0: Basic analysis and variant identification"
file $BINARY
readelf -h $BINARY 2>/dev/null | head -5
echo "    → Confirm the variant in IDA (refer to Section 1)"

echo "[*] Stage 1: Local deobfuscation with d810-ng (preferred)"
echo "    IDA → Ctrl-Shift-D load d810-ng"
echo "    Check: MBA + Opaque predicate + Unflattener"
echo "    Apply to target functions"
echo "    Save IDB"

echo "[*] Stage 2: obpo-plugin (if d810-ng is insufficient and online access is available)"
echo "    IDA → Right-click dispatcher → OBPO → Mark and process"
echo "    ⚠️ Do not use on sensitive samples (binary upload to cloud services)"

echo "[*] Stage 3: Alternative without IDA (x86/x64)"
echo "    python unflattener -i $BINARY -o deobf.bin -t <func_addr> -a"

echo "[*] Stage 4: ARM64 .so alternative without IDA"
echo "    deollvm (Unicorn) or angr Deobfuscator"

echo "[+] Done. Reanalyze in IDA to verify."
```

## 7. Common Pitfalls (Community Practical Summary)

| Issue | Reason | Solution |
|-------|--------|----------|
| angr path explosion/abnormal exit | Pluto/Polaris's **Trap Angr** pass | Switch to d810-ng or Unicorn dynamic methods |
| obpo-plugin can't connect | Server self-maintained, may be down | Use local d810-ng; can submit issue in obpo repository |
| Goron/Arkari indirect jump deflat fails | Distributor uses BR x8 instead of switch | Set data segment to read-only first, then use DeObfBR |
| d810-ng processed functions still messy | OLLVM customized pass parameters/seed | First symbolically execute to remove opaque predicates, then unflatten |
| Nested fla (multi-level flattening) not cleaned up completely | obpo/d810-ng cleans only one layer at a time | **Iterative processing**: Mark new appearing dispatchers each time |
| ARM64 .so deflat errors | Old deflat scripts only support x86 | Use d810-ng / obpo (support ARM64) / deollvm |
| Hikari strings not visible | String Encryption pass | Simulate decryption stub with Unicorn, dump decrypted strings |
| amice target deflat completely ineffective | Contains VM Flatten / Instruction Virtualization | **Not OLLVM fla**, need VM handler restoration (refer to VM reverse engineering) |
| Hodur(PugX) sample without switch distributor | Nested while(1) + jnz state | Use d810-ng **HodurUnflattener**, don't use regular Unflattener |
| Approov sample status constants show no pattern | Constants concentrated in 0xF6000–0xF6FFF | Use d810-ng **BadWhileLoop** unflattener |
| Sensitive samples misusing obpo | Binary uploaded to cloud service | Confidential/unpublished vulnerability samples **use local tools only** (d810-ng/angr) |
| Frida hook OLLVM functions hang | State variable changed causing infinite loop | Add conditional breakpoints at distributor entry to limit execution times |

---

## 8. Tool Quick Reference Table (2026 Community Activity)

| Tool | Platform | Method | Stars/Cost | Last Updated | Open Source | Remarks |
|------|----------|--------|-------------|--------------|-------------|---------|
| **obpo-plugin** | IDA | microcode+concolic (cloud) | 629 | 2026-06 | Plugin open-source/Core closed-source | Strongest effect, needs internet connection |
| **ollvm-breaker** | Binary Ninja | BN API | 441 | 2026-06 | ✅ | Android .so practical use |
| **ollvm-unflattener** | CLI | Miasm symbolic execution | 265 | 2026-06 | ✅ | x86/x64, BFS multi-layer |
| **d810-ng** | IDA | microcode+Z3 | 223 | 2026-06 | ✅ | **Preferred local tool**, broad variant coverage |
| **DeObfBR** | — | BR obfuscation specialized | 96 | 2026-06 | ✅ | Goron/Arkari indirect branch |
| **IDA_Ollvm-unflattener** | IDA | Miasm plugin version | 90 | 2026-04 | ✅ | IDA plugin wrapper for ollvm-unflattener |
| **deollvm** | CLI | Unicorn | 34 | 2026-04 | ✅ | ARM64 specialized |
| **angr** | CLI | Symbolic execution | — | Active | ✅ | General-purpose, suppressed by Trap Angr |
| **SiMBA** | CLI/Library | MBA simplification | — | — | ✅ | Expression simplification |
| **Triton** | CLI | Symbolic execution+taint | — | Active | ✅ | Dynamic symbolic execution |

## 9. References

**Obfuscators (for understanding the target):**
- [obfuscator-llvm/obfuscator](https://github.com/obfuscator-llvm/obfuscator) — Original OLLVM
- [HikariObfuscator/Hikari](https://github.com/HikariObfuscator/Hikari) — Hikari
- [komimoe/Hikari](https://github.com/komimoe/Hikari) — Arkari (based on goron, LLVM 14+)
- [amimo/goron](https://github.com/amimo/goron) — goron
- [bluesadi/Pluto](https://github.com/bluesadi/Pluto) — Pluto
- [za233/Polaris-Obfuscator](https://github.com/za233/Polaris-Obfuscator) — Polaris (original Pluto)
- [open-obfuscator/o-mvll](https://github.com/open-obfuscator/o-mvll) — O-MVLL
- [fuqiuluo/amice](https://github.com/fuqiuluo/amice) — Rust implementation of OLLVM passes
- [lich4/awesome-ollvm](https://github.com/lich4/awesome-ollvm) — **Variants Overview (strongly recommended to read first)**

**Deobfuscation Tools:**
- [obpo-project/obpo-plugin](https://github.com/obpo-project/obpo-plugin) — Strongest cloud plugin
- [w00tzenheimer/d810-ng](https://github.com/w00tzenheimer/d810-ng) — Local preferred choice
- [cdong1012/ollvm-unflattener](https://github.com/cdong1012/ollvm-unflattener) — Miasm pure script
- [amimo/ollvm-breaker](https://github.com/amimo/ollvm-breaker) — Binary Ninja
- [GeT1t/deollvm](https://github.com/GeT1t/deollvm) — ARM64 Unicorn
- [Mrack/DeObfBR](https://github.com/Mrack/DeObfBR) — BR obfuscation specialization
- [maskelihileci/IDA_Ollvm-unflattener](https://github.com/maskelihileci/IDA_Ollvm-unflattener) — IDA plugin version
- [angr](https://angr.io/) — Symbolic Execution Framework
- [SiMBA](https://github.com/tech-srl/simba) — MBA Simplification

**Academic/Blogs:**
- [Quarkslab: Deobfuscation: Recovering an OLLVM-protected program](https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html) — deflat classic principle
- [MODeflattener](https://github.com/mrT4ntr4/MODeflattener) — Static deflat (ollvm-unflattener's counterpart)

> Related Documents: [[anti-analysis.md]] (Anti-Debugging/Anti-Analysis Summary), [[tools-advanced.md]] (Advanced Toolset), [[elf-analysis.md]] (ELF File Analysis), [[ai-assisted-re.md]] (AI-Assisted Reverse Engineering)