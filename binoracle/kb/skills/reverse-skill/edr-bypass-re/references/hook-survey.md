# EDR Hook Research Quick Reference

> Limited to authorized red teams / adversarial exercises / proprietary product testing. Prohibited from use against unauthorized targets.

This document summarizes the main monitoring points of mainstream EDR/AV in user space and kernel mode, providing quick location for "what to handle" during the reconnaissance phase of a red team operation.

## 1. Mainstream EDR Fingerprint and Hook Mode Quick Reference

| Vendor/Product | User Space Component | Kernel Driver | Main Monitoring Areas |
|----------------|----------------------|---------------|-------------------------|
| CrowdStrike Falcon | `CSFalconService.exe`, `CSAgent.sys` injected into target processes | `CSAgent.sys`, `CSBoot.sys` | Re-target kernel callback + ETW-TI; user space hooking is limited (cloud-based) |
| Microsoft Defender for Endpoint (MDE) | `MsMpEng.exe`, `MpClient.dll` | `WdFilter.sys`, `WdBoot.sys`, `WdNisDrv.sys` | AMSI + ETW-TI + ntdll inline hook + kernel callback comprehensive |
| SentinelOne | `SentinelAgent.exe`, `SentinelHelperService.exe` | `SentinelMonitor.sys`, `SentinelDeviceControl.sys` | User space ntdll hooking + re-target kernel callback + custom ETW provider |
| Elastic Defend (formerly Endpoint Security) | `elastic-endpoint.exe` | `elastic-endpoint-driver.sys` | Mainly ETW + limited ntdll hooking, paired with Elastic Agent upload |
| ESET | `ekrn.exe`, `eamsi.dll` | `eamonm.sys`, `epfwwfp.sys` | Numerous user space hooks (NtCreateFile / NtOpenProcess etc.) |
| Sophos Intercept X | `SophosFileScanner.exe`, `SophosNtpService.exe` | `SophosED.sys`, `hmpalert.sys` | ntdll hooking + HMPA memory protection + kernel callback |
| Kaspersky | `avp.exe`, `klif.sys` | `klif.sys`, `klhk.sys` | Re-target user space hooking + KLIF custom micro-filtering + network filtering driver |
| Trend Micro Apex One | `TmListen.exe`, `TmCCSF.dll` | `tmcomm.sys`, `tmactmon.sys` | User space hooking + behavior monitoring driver |
| Carbon Black | `RepMgr.exe`, `RepWAV.exe` | `ParityDriver.sys` | Partially kernel callback + ETW |

### Quick Fingerprint Script

```powershell
$edrSigs = @{
    'CSAgent'           = 'CrowdStrike Falcon'
    'SentinelAgent'     = 'SentinelOne'
    'elastic-endpoint'  = 'Elastic Defend'
    'ekrn'              = 'ESET'
    'MsMpEng'           = 'Microsoft Defender'
    'SophosFileScanner' = 'Sophos Intercept X'
    'avp'               = 'Kaspersky'
    'TmListen'          = 'Trend Micro Apex One'
    'cb'                = 'Carbon Black'
}

Get-Process | ForEach-Object {
    foreach ($k in $edrSigs.Keys) {
        if ($_.ProcessName -match $k) {
            "[+] $($edrSigs[$k]) detected: $($_.ProcessName) (PID $($_.Id))"
        }
    }
}

Get-ChildItem 'C:\Windows\System32\drivers\*.sys' |
    Where-Object { $_.Name -match 'CSAgent|Sentinel|elastic|eam|WdFilter|Sophos|klif|tmcomm|Parity' } |
    Select-Object Name, VersionInfo
```

## 2. Key User Space ntdll Hook Functions

EDR almost certainly hooks the following `ntdll.dll` exports (grouped by ATT&CK behaviors):

| Function | Monitored Behavior | ATT&CK |
|----------|----------------------|--------|
| `NtCreateThreadEx` | Remote thread injection, QueueUserAPC injection | T1055.002 / T1055.004 |
| `NtAllocateVirtualMemory` | Shellcode allocation of RWX memory | T1055 |
| `NtAllocateVirtualMemoryEx` | Cross-process memory allocation (new API in Win10+) | T1055 |
| `NtProtectVirtualMemory` | Change page permissions from RW to RX | T1055 |
| `NtWriteVirtualMemory` | Cross-process writing of shellcode | T1055.012 |
| `NtMapViewOfSection` | Section-based injection (Process Doppelganging / Ghosting) | T1055.013 |
| `NtCreateSection` | Complementary to MapViewOfSection | T1055.013 |
| `NtOpenProcess` | Opening target process for handle acquisition | T1057 |
| `NtQueueApcThread` / `NtQueueApcThreadEx` | APC injection | T1055.004 |
| `NtCreateProcess` / `NtCreateProcessEx` / `NtCreateUserProcess` | Process creation (including PPID spoofing) | T1106 |
| `NtSetContextThread` | Changing thread context (thread hijacking injection) | T1055.003 |
| `NtResumeThread` | Resuming the thread after injection | T1055 |
| `NtQuerySystemInformation` | Enumerating processes / drivers / handles | T1057 / T1082 |
| `NtAdjustPrivilegesToken` | Privilege escalation to obtain SeDebugPrivilege etc. | T1134 |
| `NtLoadDriver` | Loading kernel driver (BYOVD) | T1543.003 |

### Verifying Hook Existence

```powershell
# Simple: Disassemble and diff the disk ntdll with the current process's ntdll
# 1. Get the disk ntdll
copy C:\Windows\System32\ntdll.dll C:\temp\ntdll_clean.dll

# 2. Attach to any process in WinDbg and export the .text segment of the current ntdll
# .writemem c:\temp\ntdll_live.bin ntdll!.text L?<size>

# 3. Disassemble NtAllocateVirtualMemory using IDA / radare2, normally it should be:
#    mov r10, rcx
#    mov eax, <SSN>
#    test byte ptr [...]
#    jne ...
#    syscall
#    ret
# If the first instruction becomes jmp <some address>, it indicates a hook
```

## 3. Kernel Callback Monitoring Points

Common kernel callbacks registered by EDRs (all can be unregistered using the BYOVD path in `attack-chain`, but at a high cost):

| API | Registration Timing | Defender Purpose |
|-----|-------------------|------------------|
| `PsSetCreateProcessNotifyRoutineEx` | Process creation/exit | Intercept suspicious child processes |
| `PsSetCreateThreadNotifyRoutine` | Thread creation/exit | Detect remote thread injection |
| `PsSetLoadImageNotifyRoutine` | DLL/EXE loaded into any process | Module integrity / unsigned interception |
| `CmRegisterCallback` / `CmRegisterCallbackEx` | Registry operations | Persistence detection |
| `ObRegisterCallbacks` | Handle requests for `OpenProcess` / `OpenThread` | Prevent LSASS handle acquisition (T1003.001) |
| `MmRegisterPhysicalMemoryCallback` | Physical memory mapping | Prevent DMA / memory forensics |
| `IoRegisterFsRegistrationChange` | File system registration | Minifilter coordination |
| `KeRegisterNmiCallback` | NMI (rarely used by EDRs) | Exception monitoring |
| `EtwRegister` (kernel side) | Kernel ETW reporting | Coexist with ETW-TI |

### Enumerating Registered Callbacks Using WinDbg

```text
0: kd> dx -r1 nt!PspCreateProcessNotifyRoutine
0: kd> dx -r1 nt!PspCreateThreadNotifyRoutine
0: kd> dx -r1 nt!PspLoadImageNotifyRoutine

0: kd> !object \Callback
0: kd> !object \Callback\ProcessObject
```

Or use tools like PChunter / DRVHV for a visual list of callbacks by ordinary users.

## 4. Static Dump Hook Tables (IDA + WinDbg Process)

### Workflow A: Single-Process Comparison

```text
1. Find a process already injected with an EDR user-mode component (any running process)
2. windbg attach (-pn target.exe)
3. lm m ntdll → Get the module base address
4. .writemem c:\temp\ntdll_live.bin ntdll+0x0 L?<image size>
5. Copy C:\Windows\System32\ntdll.dll to c:\temp\ntdll_disk.dll
6. Load both files in IDA, jump to NtAllocateVirtualMemory:
     - disk: standard prologue
     - live: first jmp <0x7FFE000000xx>
7. Follow the jmp target address → That's the EDR trampoline; dump it out
8. Enter the trampoline to see which DLL it lands on, confirming the EDR module name
```

### Workflow B: Batch Hook Table Generation

Using `HookHunter` or a custom script:

```powershell
# pseudo workflow, see scripts referenced for details
$disk = Get-Content C:\Windows\System32\ntdll.dll -Encoding Byte
$live = # get through OpenProcess + ReadProcessMemory
# Compare the first 16 bytes of each export in .text section
```

## 5. pe-sieve Automatic Detection

`pe-sieve` is the preferred choice for detecting EDR hooks and implants:

```powershell
# Basic scan
pe-sieve64.exe /pid 1234

# Recommended combination (includes shellcode and hook detection)
pe-sieve64.exe /pid 1234 /shellc 3 /modules 3 /imp 3 /data 3 /dir hooks_dump

# Key parameters:
#   /shellc N    shellcode scan level (0-3)
#   /modules N   module integrity check (0-3)
#   /imp N       IAT hook check
#   /data N      data segment scan
#   /dir <path>  dump output directory
```

Output will be generated in `hooks_dump/<pid>.<name>/` with `*.tag` files listing hook addresses:

```text
modified_modules.tag example:
71f10000;ntdll.dll
71f1a3b0;hook;jmp_far
71f1c020;hook;jmp_near
```

These can be directly fed into IDA to jump to the corresponding RVA for further analysis.

### Embedding pe-sieve in an Implant (Self-Check)

In practice, `pe-sieve` is often compiled as a lib (`libpe-sieve`) and used by implants to self-check when starting: if ntdll has hooks, trigger the unhook process; if it's being hooked itself, be cautious, possibly in a sandbox.

## 6. API Monitor v2 Dynamic Observation

API Monitor v2 (Rohitab) is suitable for observing where EDRs insert hooks in a lab environment:

```text
1. Start API Monitor v2 (as administrator)
2. Check the API Filter:
     - NT Native API → Memory Management
     - NT Native API → Process and Thread
     - Windows Defender / AMSI (if visible)
3. Monitor New Process → Select the implant test sample
4. Observe:
     - NtAllocateVirtualMemory call order
     - Whether it's routed through an EDR DLL
5. In the Modules tab, see which EDR DLLs are injected with LoadLibrary
```

## 7. Common EDR DLLs (User-Mode) Quick Reference

| DLL | Vendor | Notes |
|-----|--------|-------|
| `umppc*.dll` | Microsoft Defender | MpClient userland |
| `mpoav.dll` | Microsoft Defender | AMSI provider |
| `aswAMSI.dll` | Avast | AMSI provider |
| `eamsi.dll` | ESET | AMSI provider |
| `IDPMServiceClient.dll` | Sophos | HMPA injection |
| `klsihk64.dll` | Kaspersky | Injects into target processes |
| `CrowdStrike.Sensor.dll` | CrowdStrike | Older version, newer versions mainly use the kernel |
| `SentinelInjection64.dll` | SentinelOne | User-mode injection |
| `TmUmEvt64.dll` | Trend Micro | Behavior monitoring |

Confirm the target EDR before deciding which DLL to reverse for hook table extraction.

## References

- pe-sieve: <https://github.com/hasherezade/pe-sieve>
- HollowsHunter: <https://github.com/hasherezade/hollows_hunter>
- API Monitor v2: <http://www.rohitab.com/apimonitor>
- MITRE ATT&CK T1562: <https://attack.mitre.org/techniques/T1562/>
- MITRE ATT&CK T1055: <https://attack.mitre.org/techniques/T1055/>
- ired.team EDR notes: <https://www.ired.team/offensive-security/defense-evasion>

## Callback Routing

After completing the hook research, return to `SKILL.md` Step 3 and select a bypass technique combination, then execute according to `references/unhook-techniques.md` and `references/telemetry-blinding.md`.