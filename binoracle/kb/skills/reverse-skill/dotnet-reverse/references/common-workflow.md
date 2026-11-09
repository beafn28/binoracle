# General Workflow for .NET Reverse Engineering / CTF

Details of the full workflow, reliability of IL patches, extraction of string decryptors, state machine recognition, and dnlib scripting.

## Full Workflow (End-to-End)

```text
1. Identify  → Confirm it's a .NET managed program (not native)
2. Detect    → DIE / de4dot --detect detect obfuscator
3. Deobf     → de4dot deobfuscate (retain original sample)
4. Static    → dnSpyEx browse C# view to locate, IL view for key logic
5. Dynamic   → dnSpyEx debugger break at critical methods to see runtime plaintext
6. Patch     → IL editor modify, Save Module
```

Each step's output should be saved: original sample `target.exe` → deobfuscated `target-clean.exe` → patched `target-patched.exe`.

## Reliability of IL Patch vs C# Patch

**Core Conclusion: Critical modifications should use the IL editor, not the C# editor.**

| Dimension | C# Editor (Edit Method C#) | IL Editor (Edit IL) |
|-----------|-----------------------------|---------------------|
| Compilation Failure Risk | High (missing references, syntax, lambda rewrite failures)| Almost zero |
| Information Preservation | Compiler regenerates IL, may differ from original IL | Exact replacement, one instruction at a time |
| Applicability | Change a string, change a constant, simple logic | Modify conditions, delete checks, modify control flow |
| async/await/state machine | Frequently compile failures or distortions | Directly modify state machine fields, reliable |

dnSpyEx's C# decompiler is based on read-only decompilation + attempting recompilation, which easily fails for compiler-generated code (state machines, closures, `yield`). The IL editor edits instructions one by one, what you see is what you get.

### Typical IL Patch Patterns

```text
Modify a condition (if (check) → always true):
  Original: call bool Foo::Check() brfalse.s SKIP
  Modified: ldc.i4.1 ; push true brfalse.s SKIP ; now never jumps, SKIP does not execute
  Or more directly:
      ldc.i4.1 ret ; method returns true directly

Modify a condition (if (check) → always false):
  ldc.i4.0 ret

Delete entire validation:
  All nop, or change to ret + correct return value

Modify string constants:
  Modifying strings with the C# editor is usually OK (ldstr directly swaps token), but if the string is in resources/encryption, you need to modify the decryption logic

Modify numeric constants:
  Directly modify operands of ldarg / ldc instructions
```

## State Machine Recognition (async/await / yield)

C#'s `async/await` and `IEnumerator` yield compile into **state machines**: the compiler generates a nested class with `MoveNext()` using a `state` field for switch dispatch. dnSpyEx's C# view restores async, but decompilation may be distorted; the IL view of `MoveNext` is most accurate.

```text
async/await MoveNext structure:
  switch(this.<>1__state) { case 0: ... await before logic; this.<>1__state = 1; await MoveNext; case 1: ... await after logic; }

To patch async logic: modify state transfers or specific case conditions in MoveNext.
C# editor modifying async almost always fails → must use IL.
```

## String Decryptor Extraction

See `obfuscators.md` for details. Here's a dnlib script to batch decrypt strings:

```csharp
// dnlib script: scan all string decryption calls, restore at runtime and write back
// Usage: dotnet script decrypt.csproj target.exe 0x06000012
using System;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using dnlib.DotNet.Emit;

var module = ModuleDefMD.Load(args[0]);
var decryptorToken = uint.Parse(args[1], System.Globalization.NumberStyles.HexNumber);

// Find the decryption method, call it using reflection (need to load assembly into AppDomain)
// Iterate through all methods, replace call Decryptor(token) with ldstr "decrypted result"
foreach (var type in module.GetTypes())
    foreach (var method in type.Methods)
    {
        if (!method.HasBody) continue;
        var instrs = method.Body.Instructions;
        for (int i = 0; i < instrs.Count; i++)
        {
            // Identify call decryption pattern, call decryptor to get plaintext, replace with ldstr
            // (Omitted boilerplate for calling the decryptor using reflection, idea: load original assembly → MethodInfo.Invoke to get plaintext → instrs[i] = OpCodes.Ldstr + operand=plaintext)
        }
    }

var opts = new ModuleWriterOptions(module);
module.Write("target-decrypted.exe", opts);
```

dnlib is the de facto standard for .NET metadata programming, and de4dot internally uses it. When writing custom deobfuscation scripts, prefer dnlib.

## Dynamic Debugging Tips

dnSpyEx debugger is much friendlier to .NET programs than native:

- **Breakpoints at method entry**: Right-click method → Add Breakpoint
- **View object values**: Directly view object fields and string contents in Locals / Watch window after breaking
- **Memory write**: Can directly change runtime variable values (Edit Value)
- **Exception breakpoints**: Debug → Exceptions, check the exception types to break on — obfuscators often use exceptions to drive control flow; breaking on exceptions shows the real path

### Exception-driven Control Flow

Some obfuscators embed normal logic inside `try`, using `throw` + `catch` for jumps. Looking at IL statically might look like exception handling, but it's actually control flow:

```text
try { throw new CustomException(0x42); } catch (CustomException e) { switch(e.Code) { case 0x42: real logic A; break; case 0x43: real logic B; break; } }
```

Set an exception breakpoint (break on `CustomException`), track the `Code` value flow, faster than hard-parsing IL.

## Module Initializer (.cctor)

`.NET` module's static constructor (`<module>`'s `.cctor`) is executed first when the assembly loads, where obfuscators often place anti-tamper / decryption initialization. Analysis order:

```text
1. First look at <module>.cctor (Module .cctor) — decryption/anti-debug initialization
2. Then look at Program.Main / Startup
3. Anti-tamper in .cctor → patch .cctor first before deobfuscating
```

## General Pattern for Extracting Configuration / C2 / Key

Red team tools and loaders often embed encrypted configuration in resources or fields, decrypted at runtime:

```text
Location flow:
1. strings look for plaintext URL/IP (usually absent after obfuscation)
2. Find byte[] field + decryption method (AES/XOR)
3. Dynamically break at the return point of the decryption method to dump the decrypted plaintext
4. Common: AES-256-CBC with Key==IV (Codegate 2013 pattern, see reverse-engineering/tools.md .NET section)
```

Refer to the specific configuration structure in `references/sharp-tools.md` for red team tools.

## Boundary with Reverse-Engineering

- **IL2CPP / NativeAOT** → Compiled to native, no CLR metadata → Go to `reverse-engineering/` (IDA/r2), this skill is for recognition only
- **Managed .NET**（Standard C# exe/dll, Mono/Unity managed layer, Xamarin）→ This skill
- **Hybrid (native loader + .NET payload)** → Loader part goes to `reverse-engineering/`, dump out .NET payload and switch to this skill

## Output List for Disk

For each .NET reverse engineering task, suggest producing:
- `target-original.exe`（Original sample, untouched）
- `target-clean.exe`（de4dot deobfuscated）
- `notes.md`（Identified obfuscators, decryption tokens, key method addresses, configuration/C2/key）
- `target-patched.exe`（Patched if needed）
- `il-diff.txt`（IL comparison before and after patching, if doing a patch）