# Detailed Analysis of .NET Obfuscation Techniques

Reverse-engineering and CTF techniques for mainstream .NET obfuscators, including deobfuscation. Core tools: **de4dot** (automatically identifies most shells) + **dnSpyEx** (manual patching) + **dnlib** (script-based).

## Decision Table

| Obfuscator | de4dot type | Typical Features | Automatic Decryption | Manual Points |
|------------|-------------|------------------|----------------------|---------------|
| ConfuserEx 1.x/2.x | `cfze` | anti-tamper, control flow obfuscation, string encryption, anti-debugging | [OK] Most automatic | New versions need to be patched for anti-tamper |
| ConfuserEx 3.x / Custom | `cfze` | Same as above + custom protector | [WARN] Partial | Runtime dump / dnlib |
| SmartAssembly | `sa` | String encoding, resource compression, method call hiding | [OK] Automatic | Resource extraction |
| Babel.NET | `babel` | Method body encryption, control flow, strings | [OK] Automatic | — |
| Eazfuscator.NET | `eaz` | String/resource encryption, expression obfuscation | [WARN] Partial | String decryption tool |
| .NET Reactor | `reactor` | necrobit (code segment encryption) + anti-tamper | [WARN] New versions difficult | Runtime dump + rebuild metadata |
| Themida .NET | — | Shell + virtualization | [FAIL] de4dot doesn't work | Memory dump, native approach |
| Agile.NET / CliSecure | `agile` | Method body encryption | [OK] Automatic | — |

## Standard Usage of de4dot

```powershell
# Automatic detection (usually sufficient)
de4dot target.exe -o target-clean.exe

# Explicitly specify type (automatic detection fails)
de4dot --type cfze target.exe -o target-clean.exe

# Probe shell type first
de4dot --detect target.exe

# Batch processing
de4dot *.exe

# Decrypt only strings, leave control flow intact (minimal intervention)
de4dot --strtyp delegate --strtok METHOD_TOKEN target.exe
```

de4dot's `--strtyp` / `strtok` modes: Only decrypts string decryption methods (specifies the decryption method token), preserving original control flow. Suitable for scenarios where "you only want to see plain text strings but don't want to touch anti-tamper."

---

## ConfuserEx (Most Common)

### Feature Recognition

- Entry module `<module>` class with `[MethodImpl(NoInlining)]` anti-tamper check
- Large number of `Dictionary<string, T>` string decryption calls
- Control flow flattening (switch dispatch + state variables)
- Embedded `.cmp` compressed resources in resources
- dnSpyEx C# view: Class/method names garbled (`\uXXXX` or meaningless characters), method bodies filled with `int num = ...; switch(num)`

### Decryption Process

```powershell
# 1. Standard decryption
de4dot target.exe -o target-clean.exe

# 2. If de4dot reports "unknown" or the decrypted file cannot be opened → New version/Custom ConfuserEx
#    First confirm anti-tamper:
dnSpyEx open → Find Module .cctor or Main with integrity check
```

### Anti-Tamper Bypass (Common for Newer ConfuserEx)

ConfuserEx's `anti tamper` checks method body hashes at runtime, crashing if modified. de4dot usually handles old versions, but newer versions need manual intervention:

```text
Method A — dnSpyEx directly patch the validation function:
  1. Find anti-tamper validation method (usually called in <module>'s static constructor)
  2. IL edit: Change the body of the validation method to ret (direct return)
  3. Save → Re-run de4dot

Method B — Runtime dump:
  1. Use MegaDumper / ExtremeDumper to run and dump the assembly from memory
  2. The dumped assembly is already decrypted, clean up the remnants with de4dot
```

### After Control Flow Restoration

de4dot will restore flattened switch dispatch back to normal if/while. If not fully restored (seeing residual state machines), rerun de4dot or manually debug IL.

---

## SmartAssembly

```powershell
de4dot --type sa target.exe -o target-clean.exe
```

Features:
- Strings encoded with `SmartAssembly.Runtime.Strong` series
- Resource compression (`{assembly}.Resources`)
- Method call hiding (`ProcessCaller` / indirect calls)

de4dot has the best compatibility with SmartAssembly, basically a one-click solution.

---

## .NET Reactor (necrobit)

`.NET Reactor`'s **necrobit** encrypts real method bodies and stores them in resources, decrypting and injecting at runtime. Original method bodies are empty shells. de4dot works well with old versions but often fails with new versions (4.x+).

```text
When de4dot fails:
1. Let the program run (dotnet target.exe or double-click)
2. MegaDumper / ExtremeDumper dump process memory → Export decrypted assembly
3. Use de4dot to clean up the residual obfuscation in the dump
4. If metadata is damaged, rebuild with dnlib (see common-workflow.md)
```

---

## Manual Extraction of String Decryptors

Obfuscators encrypt strings and call decryption methods at runtime to restore them. de4dot usually automatically recognizes decryptors; if it fails, do it manually:

```text
1. Find the decryption method in dnSpyEx (usually with a fixed signature: static string Decrypt(int) or Decrypt(string, int))
   - Features: Highly called, parameters are constant numbers, returns string
2. Note down the method token (e.g., 0x06000012)
3. Specify the decryptor in de4dot:
   de4dot --strtyp delegate --strtok 0x06000012 target.exe -o target-clean.exe
```

If even the decryption method itself is obfuscated (control flow flattened), first deobfuscate control flow to locate the decryptor.

## Common Anti-Debugging Techniques

| Technique | Location | Bypass |
|-----------|----------|--------|
| `Debugger.IsAttached` check | Any method | Modify IL to `ldc.i4.0; ret` or patch getter |
| `Debugger.IsLogging` | — | Same as above |
| Time detection (`DateTime.Now` difference) | Method entry | Patch the time comparison |
| `CheckRemoteDebuggerPresent` P/Invoke | — | Nop the call |
| Exception-driven control flow (try/catch path selection) | Main logic | Cannot simply nop; analyze the true path in the catch block |

> .NET anti-debugging is simpler than native — most are managed API calls, which can be modified in dnSpyEx with a single line.

## Retreat Options When de4dot Fails

1. **de4dot --detect** Check detection results and refer to the table above
2. **Runtime dump** (MegaDumper / ExtremeDumper / Process Hacker export module)
3. **dnlib script** Manual decryption (see dnlib section in common-workflow.md)
4. **Dynamic priority**: Run the program and set a breakpoint at the decryption point to directly see plain text, no need for deobfuscation

Community references: Washi blog {misconceptions-about-dotnet} (common misconceptions in IL analysis), KX.NET Reversing forum, Guided Hacking {Top 5 .NET RE Tools}.