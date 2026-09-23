---
name: thick-client
description: Use for authorized security testing of desktop thick clients including local storage, update channels, IPC, traffic, and client-side trust boundaries.
---

# Thick Client Security Testing

## ACTION REQUIRED (Read and execute immediately after reading)

1. `NOW`: Read the file `../field-journal/precedent-pentest.md`
2. `NOW`: Confirm that the target is a **desktop thick client** (GUI or service-attached for Windows/macOS/Linux), not pure web.
3. `NOW`: Case-init; set package source and test account in scope
4. `NEXT`: Tools (Burp upstream proxy, process monitoring, reverse engineering tools)
5. `ACT`: Trust boundary map → Local face → Network face → Update/Supply chain

## Applicable Scenarios

- C/S architecture clients, Electron/.NET WinForms/WPF, Qt, .NET WinForms/WPF
- Local configuration/credential storage, IPC, named pipes
- Client-side mandatory validation bypass research (authorization)
- Study of automatic update channels and code signing verification

## Workflow

### 1. Define Boundaries

```text
□ Process tree, child processes, drivers/services
□ Listening ports and outbound domain names
□ Local sensitive paths: %APPDATA%, Keychain, registry
```

### 2. Local Attack Surface

```text
□ Plain configuration, hardcoded keys, debug switches
□ DLL hijacking/search order (Windows)
□ Database files (SQLite) permissions and encryption
□ IPC: Who can connect? Authenticated?
```

### 3. Network Face

```text
□ System proxy / application-defined TLS
□ Certificate pinning → mobile/js method or Frida approach
□ API overreach: Hidden management interfaces on the client side
```

### 4. Reverse Validation

```text
□ .NET → dotnet-reverse; native → ida/ghidra; Electron → asar + js-reverse
```

## Toolchain

| Tool | Purpose |
|------|---------|
| Process Monitor / API Monitor | Behavior monitoring |
| Burp / mitmproxy | Traffic analysis |
| dnSpy / IDA / Ghidra | Reverse engineering |
| Sysinternals | Windows-specific tools |
| asar / nexe detection | Electron-specific tools |

## References

- `references/thick-client-checklist.md`
- `../dotnet-reverse/` `../ida-reverse/` `../js-reverse/` `../api-security/`

## Context Routing

**Upstream**: MASTER R32  
**Downstream**: Pure protocol `protocol-reverse`; supply chain update `supply-chain-security`

## Task Completion Self-Check

- [ ] Have you drawn out the trust boundaries?
- [ ] Are both local and network faces covered? 
- [ ] Checklist?