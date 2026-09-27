# [Seed] Unity IL2CPP Game Reversing → Restore Metadata + Modify Logic

## Scenario Classification
Game Security / Mobile Reversing

## Target Overview
A Unity-packaged Android game (IL2CPP mode), with in-app purchases or core algorithms written in C# but compiled to native. The goal is to restore method names, locate key logic, modify/patch the implementation.

## Complete Execution Chain

1. Unpack APK and confirm it's IL2CPP
   ```bash
   unzip target.apk -d apk
   ls apk/lib/arm64-v8a/        # See libil2cpp.so which indicates IL2CPP
   ls apk/assets/bin/Data/Managed/Metadata/
   # Key file: global-metadata.dat
   ```
2. Use **Il2CppDumper** to restore metadata
   ```bash
   Il2CppDumper libil2cpp.so global-metadata.dat output/
   # Output: DummyDll/ + script.json + il2cpp.h + dump.cs
   ```
3. Run the IDA IL2CPP script (`ida_with_struct.py`)
   - Load libil2cpp.so → File → Script File → Select ida_with_struct.py → Select script.json
   - IDA can now see C# method names, signatures, and strings
4. Search for business keywords in dump.cs (e.g., `AddCoin` / `OnPurchase` / `Verify` / `IsVip` / `CheckSign`)
5. Get the offset of key methods → Jump to disassembly/decoding in IDA
6. Choose a modification method:
   - **Static patch**: Directly change the judgment in IDA to `mov w0, #1; ret`
   - **Dynamic hook**: Use Frida to intercept IL2CPP methods (with Frida-Il2CppBridge)
7. Repackage and validate / inject validation

## Pitfall Records

| Issue | Cause | Solution | Time |
|-------|-------|----------|------|
| Il2CppDumper reports metadata version not supported | Newer Unity changed the metadata format | Upgrade Il2CppDumper to latest or use Il2CppInspectorRedux | 30min |
| global-metadata.dat is encrypted | Used AntiCheatToolkit / custom encryption | Find the decryption function during game initialization (usually around il2cpp_init) → Frida dump after mmap | 2h |
| dump.cs shows method names but IDA doesn't match | script.json inconsistent with so | Must use the same dump output; clear cache when switching IDA | 20min |
| Frida hooking IL2CPP methods fails | IL2CPP method is not standard Java/ObjC, need to calculate method offset | Use frida-il2cpp-bridge library, don't hardcode Interceptor.attach | 1h |
| Patch causes game crash | Hash verification or anti-tamper | Patch the hash verification logic as well, or use hook without changing the file | 2h |
| Repackaging crashes on startup | apksigner v2 can't re-sign after modifying bytes | Delete META-INF + apktool b + apksigner sign in one go | 30min |

## Toolchain Discovery

- **Il2CppDumper**: A classic choice but still the default
- **Il2CppInspectorRedux**: More modern, supports newer Unity, can output scripts for IDA / Ghidra / Binary Ninja
- **frida-il2cpp-bridge**: The de facto standard for hooking on IL2CPP, much stronger than plain Frida
- **DnSpy** / **dnSpyEx**: Used to view DummyDll (the pseudo .NET assembly from dump)
- **UnityCheat** series of auxiliary tools (GameGuardian not expanded)

## Key Code/Commands

frida-il2cpp-bridge hook example:

```typescript
// hook.ts
import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    const Assembly = Il2Cpp.domain.assembly("Assembly-CSharp").image;

    // hook static method
    const PlayerData = Assembly.class("PlayerData");
    PlayerData.method("AddCoin").implementation = function (n: number) {
        console.log("[+] AddCoin called with:", n);
        return this.method("AddCoin").invoke(99999); // change to 99999
    };

    // hook instance method
    const Purchase = Assembly.class("Purchase");
    Purchase.method("VerifyReceipt").implementation = function () {
        console.log("[+] VerifyReceipt → always true");
        return true;
    };
});
```

```bash
# compile + inject
npm install frida-il2cpp-bridge
frida-compile hook.ts -o hook.js
frida -U -f com.target.game -l hook.js --no-pause
```

IDA static patch:

```text
1. Open libil2cpp.so, run il2cpp_load_metadata.py
2. Jump to the offset corresponding to IsPurchaseValid in dump.cs
3. Change the function start to MOV W0, #1; RET (ARM64)
4. Apply Patches → Save → Replace back into APK → Re-sign
```

## Suggestions for Improvements

- `reverse-engineering/SKILL.md` already covers Unity but lacks an **complete workflow** case for IL2CPP
- `reverse-engineering/references/il2cpp-cheatsheet.md` should be a separate document: dump tool comparisons, frida-bridge template, metadata encryption handling
- Add frida-il2cpp-bridge to bootstrap manifest

## Reusable Patterns/Script Snippets

**IL2CPP Standard Workflow**:

```text
1. Confirm IL2CPP (check for libil2cpp.so under lib/abi)
2. Find the metadata (assets/bin/Data/Managed/Metadata/global-metadata.dat or encrypted)
3. Il2CppDumper / Inspector restore
4. IDA + script to bring back metadata info
5. Search dump.cs for business keywords
6. Choose patch or hook
7. Validate (start + real scenario)
```

**Metadata Encryption Handling**:

```text
1. Hook fopen/open system calls in Frida to see who reads global-metadata.dat
2. Dump the decrypted metadata from memory after mmap/read
3. Feed the dumped memory as metadata to Il2CppDumper
```

## Evolution Actions
- [ ] reverse-engineering/references add an il2cpp complete chapter
- [ ] bootstrap-manifest include frida-il2cpp-bridge / Il2CppInspectorRedux
- [x] The routing matrix already includes Unity / IL2CPP

## Environment Information
- Windows / macOS (to run Il2CppDumper), target device Android arm64
- IDA Pro 7.7+ or Ghidra 11+
- frida-tools 16.x, frida-il2cpp-bridge 0.9+
- Unity versions: 2019.x - 2022.x (different metadata format slightly different)

## Desensitization Requirements
This entry is seed data based on public technical patterns and does not involve any real games. The package name `com.target.game` is a placeholder.