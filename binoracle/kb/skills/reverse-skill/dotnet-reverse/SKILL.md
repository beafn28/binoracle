---
name: dotnet-reverse
description: .NET / C# binary reverse-engineering. Use when the target is a .NET assembly (PE header contains CLR, .exe/.dll managed programs), C# compiled products (contains NativeAOT), red team Sharp* tools (Rubeus / SharpHound / SharpHound etc.), .NET obfuscators (ConfuserEx / SmartAssembly / Babel / Eazfuscator), .NET loader / info-stealer / shell malware. Prioritize using dnSpyEx + de4dot, and link to dnSpy MCP when AI direct operation is required. Not used for pure native binaries (use reverse-engineering / ida-reverse).
license: MIT
compatibility: Requires a filesystem-based code agent or CLI with shell access, Windows host preferred (dnSpyEx is a Windows GUI); Linux/macOS can use ILSpy/de4dot CLI + mono/dotnet runtime.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# .NET / C# Reverse Engineering Job Guidelines

## ACTION REQUIRED（Read immediately and execute）

1. `NOW`: Use DIE/`file`/CLR header to confirm the target is a .NET managed program (otherwise SWITCH to `ida-reverse/` / `reverse-engineering/`)
2. `NOW`: If suspected of obfuscation → first deobfuscate with `de4dot`, producing `*-clean.exe`, retaining the original sample
3. `NEXT`: dnSpyEx (or dnSpy MCP / `ilspycmd`) static: C# browsing + **IL view** to see key judgments
4. `ACT`: For plain text/C2, perform dynamic debugging; for changing logic, **IL patching** is prioritized over C# recompilation
5. At the end of each phase, provide the user with 3–6 next steps menu items (including report export)

## Scope of Application

Prioritize using this skill when the task belongs to any of the following scenarios:

- Identify and reverse .NET / C# compiled products (managed PE / .exe / .dll)
- Analyze red team Sharp* toolchains (Rubeus, SharpHound, SharpShell etc.)
- Deobfuscate ConfuserEx / SmartAssembly / Babel / Eazfuscator / .NET Reactor shells
- Reverse .NET loader / info-stealer / RAT decryption and C2 logic
- Patch C# programs (change conditions, constants, keygens)
- Analyze Mono/Unity managed layers before IL2CPP compilation (note: IL2CPP compiled code is native, use `reverse-engineering/` + seed-014)

If the target is a pure native binary (C/C++/Go/Rust compiled, no CLR), please switch to `reverse-engineering/`, `ida-reverse/`, or `radare2/`.

## Core Principles

- **Identify before acting**: First confirm it's a .NET managed program (PE header contains CLR + `#~` / `#Strings` stream + mscoree `_CorExeMain`), then decide to use dnSpy instead of IDA
- **IL over C#**: The dnSpyEx C# decompiler loses/distorts information (compiler-generated state machines, async/await, yield); key judgments and patches must be done in the **IL editor**, while the C# view is only for quick browsing
- **de4dot first**: When encountering an obfuscator, first deobfuscate with `de4dot` once before static analysis; otherwise, strings and control flow will be all jumbled
- **Link to MCP**: If dnSpy MCP (tools prefixed with `dnspy_*`) is registered in the environment, prioritize using MCP for decompilation / IL inspection to avoid switching between GUIs
- **Evidence-based output**: All deobfuscated products, extracted configurations/C2/keys, and patch diffs must be saved

## Toolchain Mapping

| Capability | Preferred | Notes |
|------------|-----------|-------|
| Decompilation + Debugging + Patching | **dnSpyEx** | Top choice, unique GUI with IL editor; old dnSpy is discontinued, use the Ex branch |
| Lightweight CLI / headless decompilation | **ILSpy** (`ilspycmd`) | Suitable for batch processing, scripting, Linux/macOS |
| Deobfuscation | **de4dot** | Default solution for mainstream shells like ConfuserEx and SmartAssembly |
| Obfuscator detection | **Detect It Easy (DIE)** / **file** | First determine the shell type before deciding on de4dot parameters |
| Programmatic IL manipulation | **dnlib** | Write C# scripts to batch modify metadata/strings, create decryption tools |
| AI direct operation | **dnSpy MCP** | Tools like `dnspy_decompile` / `dnspy_inspect_il` for direct AI interaction |

> Prerequisites: Install dnSpyEx + de4dot on Windows (using choco or release); use `ilspycmd` + `dotnet runtime` on Linux/macOS. See the installation matrix in `references/sharp-tools.md`.

## Six-Stage Workflow

### 1. Identify（识别 .NET）

Confirm the target is a managed program, not a native PE:

```powershell
# Windows
file target.exe                       # "PE32 executable ... for MS Windows" insufficient
# Key: Check if there's a CLR
powershell -c "[System.Reflection.AssemblyName]::GetAssemblyName('target.exe')"
# Or
dnSpyEx drag and drop —— Openable = Managed

# General
strings target.exe | grep -iE "mscoree|_CorExeMain|mscorlib|System\\."
```

**.NET Identification Flags:**
- PE Header `Data Directory[14]` (CLR Runtime Header) non-zero
- `mscoree.dll` import / `_CorExeMain` entry point
- `#~`、`#Strings`、`#US`、`#GUID`、`#Blob` metadata streams
- `mscorlib` / `System.Private.CoreLib` strings

**NativeAOT Exception:** Compiled to native, no CLR header, but has `System.Private.CoreLib` strings and refactored type metadata —— These go to `reverse-engineering/` (IDA/r2), this skill only provides identification hints.

### 2. Detect（检测混淆器）

```powershell
# DIE quick detection
diec target.exe                        # Detect It Easy CLI
# Or drag into dnSpyEx, see if there are many obfuscated class names / control flow transformations
```

Common Obfuscators → Decryption Strategies (see `references/obfuscators.md`):

| Obfuscator | Feature | de4dot Handling |
|------------|---------|----------------|
| ConfuserEx (1.0.0 / 2.x) | `<module>` anti-tamper, control flow transformations, string encryption | `de4dot target.exe` usually auto-identifies |
| SmartAssembly | `circular`/`string encoding`, resource compression | `de4dot target.exe` |
| Babel.NET | Method body encryption, control flow | `de4dot target.exe` |
| Eazfuscator.NET | String/resource encryption | `de4dot`, some versions need manual handling |
| .NET Reactor | anti-tamper + necrobit | `de4dot`, newer versions may fail requiring manual handling |

### 3. Deobfuscate（脱混淆）

```powershell
# de4dot defaults to auto-identifying most shells
de4dot target.exe -o target-clean.exe

# Specify type (when auto-identification fails)
de4dot --type cfze target.exe          # ConfuserEx
de4dot --type sa target.exe            # SmartAssembly

# Multi-layer obfuscation / de4dot reports unknown
de4dot --detect target.exe             # See what it identifies as
# May need to patch anti-tamper before de4dot (see `references/obfuscators.md`)
```

Output: `target-clean.exe`, use this for subsequent analysis. **Keep the original sample** for reference.

### 4. Static Analyze（静态分析）

Load the decompiled sample in dnSpyEx:

- **C# View**: Quickly browse class structure, method signatures, strings (for locating)
- **IL View**: Key judgments, encryption logic, state machines must be viewed in IL (right-click → Edit IL or IL View)
- Find entry points: `Main` / `Startup` / module initializer (`Module .cctor`)
- Find critical logic: search for `flag`, `password`, `verify`, `check`, `encrypt`, `http`, `Config`

```text
Locate string → Backreference → Find the method using it → IL View to see judgment logic
```

### 5. Dynamic（动态调试）

Use dnSpyEx Debugger: Attach process / start debugging, set breakpoints on key methods, observe runtime:
- Decrypted plain text strings (many obfuscators decrypt strings at runtime)
- C2 addresses, configuration decryption results
- Exception-driven control flow (anti-debug often uses `try/catch` to hide the true path)

> .NET dynamic debugging is much friendlier —— Can directly see object values and string contents. Prefer dynamic over static.

### 6. Patch（按需修改）

```text
dnSpyEx → Right-click method → Edit Method (C#) or Edit IL
  - Change judgment: ldc.i4.0 → ldc.i4.1 (false→true)
  - Change constant: directly edit strings/numbers
  - Remove validation: nop out the entire segment
File → Save Module → Replace original file
```

**IL patch reliability > C# patch**: C# recompilation may fail (missing references, syntax issues), IL editing is almost never distorted. See `references/common-workflow.md`.

## Trigger Scenarios

When users say these, enter this skill:
- ".NET / C# 二进制逆向" / "C# 程序反编译"
- "dnSpy 分析" / "dnSpyEx patch"
- "ConfuserEx / SmartAssembly / Babel 脱混淆 / 脱壳"
- "Sharp* 工具分析"（Rubeus / SharpHound / SharpShell）
- ".NET malware / loader / info-stealer 逆向"
- "C# 程序 patch / keygen / 修改判断"

## When to Switch Out

- IL2CPP compiled Unity games → `reverse-engineering/` + `seed-014_unity-il2cpp-reverse.md` (IL2CPP is native, doesn't use dnSpy)
- NativeAOT products → `reverse-engineering/` (same as above, native)
- Pure native PE (no CLR) → `reverse-engineering/` / `ida-reverse/`
- Need to migrate symbols/functions in bulk to another version → `binary-diff/`
- Need to draw attack paths/call graph diagrams → `diagram-generator/`

## Routing Context

**Upstream Entry**: `skills/SKILL.md` (overall control), `routing.md`
**Downstream Exits**:
- IL2CPP / NativeAOT (native) → `reverse-engineering/`
- Deep native .so/.dll segment analysis → `ida-reverse/` / `radare2/`
- Need AI to directly operate on dnSpy → Register and link dnSpy MCP (see `references/sharp-tools.md`)

**Siblings**: 
- `reverse-engineering/languages-compiled.md` (.NET introduction points to this module)
- `apk-reverse/` (Xamarin/MAUI Android reverse can switch back to this module for the C# layer)

## Reference Documents

- [references/obfuscators.md](references/obfuscators.md) — ConfuserEx / SmartAssembly / Babel / Eazfuscator / .NET Reactor deobfuscation details + anti-tamper bypass
- [references/common-workflow.md](references/common-workflow.md) — Full workflow, IL patch reliability, string decryptor extraction, state machine recognition
- [references/sharp-tools.md](references/sharp-tools.md) — Red team Sharp* tool analysis, tool installation matrix, dnSpy MCP integration, community resource index

## Task Completion Self-Check

- [ ] Have you confirmed the CLR / managed identity (or already SWITCHED out of this skill)?
- [ ] Has the obfuscated sample been de4dot / equivalent shell-decompiled before deep analysis?
- [ ] Have key logic been verified using the IL view (not just C# pseudo-code)?
- [ ] Have the products (clean sample / config / patch diff) been saved and reproducible?
- [ ] Did you provide a next step menu or report exit?