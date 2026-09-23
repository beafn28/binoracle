---
name: reverse-skill-router
description: Routes reverse engineering, exploitation, penetration testing, malware, mobile, firmware, browser automation, documentation, and security tasks to the appropriate specialist skill. Use when a task spans modules or the correct reverse-skill entrypoint is unclear.
---
# Reverse Engineering Skills Master Control

This directory contains a series of skill modules related to reverse engineering, each subdirectory being an independent module containing `SKILL.md` describing its applicable scenarios, toolchain, and workflow.

## CRITICAL: Routing Execution Contract (must be executed immediately)

After reading this file, do not reply with "read/understood" alone. Execute in order:

1. `NOW`: Run the platform native router (`scripts/master-route.ps1` for Windows; `scripts/master-route.sh` for Linux/macOS/Kali), setting PRIMARY from `config/routing.json`. If issues arise, revisit `routing.md` Appendix III.
2. `NOW`: Platform native `case-init` lands the current analysis project's `work/<case>/scope.md`; **auth not granted prohibits access to target ACT**. Use `offline-sample` preset + explicit sample for local offline samples; Force must not bypass hard gates.
3. `ACT`: Immediately open PRIMARY `SKILL.md` and execute ACTION REQUIRED.
4. `NEXT`: Tool paths only recognize `tool-index.md`; missing tools → platform native bootstrap (manifest only).
5. Conclude with Evidence→Finding→Path. Reports/journals are SHOULD, unless the user requires deliverables.

**Identity**: See `ops/IDENTITY.md` (lightweight routing package + tool bootstrapping + journal; **not** Z3r0-style platform).

If routing cannot be hit, must first connect to the internet to supplement methodology and propose adding a new skill. Prohibit forcing into mismatched modules.

## Instruction Semantic Level (RFC 2119)

- `MUST`: Must execute, failure if violated.
- `MUST NOT`: Prohibited from executing, security violation if violated.
- `SHOULD`: Should be done in principle; must explain reasons for not doing so.
- `MAY`: Optional actions.

## Current Module

| Module | Directory | Applicable Scenarios |
|--------|-----------|----------------------|
| **General Reversing** | `reverse-engineering/` | GDB / Frida / angr / Unicorn / Qiling / Reverse Analysis Adversary / Multi-Language Platform Reversing / CTF Mode Library |
| **APK Reversing** | `apk-reverse/` | Android APK Unpacking, jadx De-compilation, smali Modification, Frida Hook, Repackaging, Signing, and Installation |
| **.NET / C# Reversing** | `dotnet-reverse/` | Managed PE Reversing, dnSpyEx + de4dot Deobfuscation (ConfuserEx/SmartAssembly/Babel), IL Patch, Sharp* Red Team Tool Analysis, dnSpy MCP Integration |
| **IDA Pro Reversing** | `ida-reverse/` | IDA Pro MCP HTTP Server (72 Tools): De-compilation, Disassembly, Data Flow Tracking, Cross-References |
| **Frontend JS Reversing** | `js-reverse/` | Browser Signature Location, Encryption Parameter Analysis, Runtime Sampling, Node Environment Replication; Prioritize Existing `js-reverse_*`, Use jshookmcp for Stronger Browser/CDP/Hook Needs When Available |
| **radare2 Analysis** | `radare2/` | CLI Binary Reconnaissance, Disassembly, Patch: r2 / rabin2 / rasm2 / radiff2 |
| **CTF Entry** | `ctf-sandbox/` | Single PRIMARY; Downstream in sidecar `../CTF-Sandbox-Orchestrator/` |
| **Technical Documentation Writing** | `docs-generator/` | Automatically Generate Reversing Reports, Penetration Reports, CTF Writeups, Signature Reversing Reports After Tasks Complete |
| **Evidence Graph Review** | `case-review/` | Verify Scope, Evidence→Finding→Path Traceability, Workitems, Timeline with Artifact Hashes |
| **Browser and Desktop Automation** | `browser-automation/` | Browser Operations (Playwright) + Windows Desktop Application Operations (OpenReverse UIA/CUA) + Network Observation |
| **Cross-Version Symbol Migration** | `binary-diff/` | Migrate Old Symbols to New Versions, Infer Missing PDBs, Batch Rename Function Names After Program Updates |
| **N-day Patch Diff → Exploit** | `patch-diff-exploit/` | Locate Vulnerability Points from Vendor Patches, Write PoCs, N-day Weaponization (Divided Work with binary-diff: This Skill Focuses on the Attack Side) |
| **RE → Exploit Chain** | `pwn-chain/` | Walk From Reversing to Usable Exploits: Stack/Heap/Kernel Pwning, pwntools, libc-database, CTF to Stable Remote Exploitation |
| **Firmware Penetration Chain** | `firmware-pentest/` | OWASP FSTM 9-Stage Process: Extraction → EMBA Automation → Firmadyne/QEMU Simulation → AFL++ Fuzzing → Real Machine Exploitation |
| **EDR Bypass Reversing** | `edr-bypass-re/` | Red Team Scenario: Reverse EDR Hook Tables/ETW/AMSI → Direct Syscall / Hell's Gate / Hardware Breakpoints / Call Stack Spoofing |
| **Penetration Testing Toolchain** | `pentest-tools/` | 20+ Penetration Tools (Nmap/Nuclei/SQLMap/FFUF/Hashcat/Pentest Swarm) Exposed to AI via MCP |
| **Chart Generation** | `diagram-generator/` | Generate Mermaid/Graphviz/PlantUML Diagrams from Natural Language (Attack Path Diagrams, Data Flow Diagrams, Architecture Diagrams, State Machines) |
| **Attack Chain Orchestration** | `attack-chain/` | Total Commander for Multi-Stage Attack Path Planning and Execution; Full Penetration, HW Drills, Cross-Phase Tasks Begin Here |
| **LLM/AI Security Testing** | `llm-security/` | OWASP LLM + ASI Top 10: Prompt Injection, Tool Abuse, Memory Poisoning, Agent Hijacking, System Prompt Extraction, **Agent Compliance Engineering** |
| **API Security Testing** | `api-security/` | REST/GraphQL/WebSocket Protocols: BOLA/IDOR, JWT/OAuth Attacks, 10-Stage Methodology |
| **Supply Chain Security** | `supply-chain-security/` | SBOM/SCA/CI-CD Pipelines: Dependency Scanning, Container Security, Build Integrity, Vulnerability Reachability Verification |
| **Mobile Reversing Engineering** | `mobile-reverse/` | Android + iOS: Frida/Objection Dynamic Instrumentation, SSL Pinning/Root/Jailbreak Detection Bypass, OWASP MASTG |
| **Malware Analysis** | `malware-analysis/` | Sample Analysis Six-Stage Process, YARA/Sigma, Reverse Engineering Detection, Sandbox Orchestration |
| **DSL Virtual Machine Reversing** | `reverse-engineering/dsl-vm-reverse/` | JS Custom Instruction Set VM (IIFE + switch-case Opcode); Risk Management / CAPTCHA Engines, etc. |
| **Ops Contract** | `ops/` | Scope / Evidence Chain / Roles / Timeline / Identity / Skill Supply Chain Security |
| **Community Skill Comparison** | `references/community-security-skills.md` | External Security Skills Index and Adherence Rules (Prohibit Blind Installation) |
| **Skill Supply Chain** | `ops/skill-supply-chain.md` | External Skill/MCP Installation Gateways (AST10 Simplified) |
| **RE Phase Gateway** | `reverse-engineering/references/re-agent-workflow.md` | Triage→Static→Dynamic→Synthesis |
| **Authorization Reconnaissance Pipeline** | `pentest-tools/references/recon-pipeline.md` | Scope Gate + Hit≠Verify |
| **Protocol Reversing** | `protocol-reverse/` | Custom Binary Protocols / Protobuf / gRPC / PCAP Frame Layouts |
| **Ghidra Reversing** | `ghidra-reverse/` | Open Source De-compilation, Headless, Ghidra MCP (Primary Entry Without IDA) |
| **Binary Ninja Reversing** | `binary-ninja-reverse/` | HLIL/MLIL/LLIL, Python API, and Optional Community MCP/localhost HTTP Integration |
| **Cloud / Container / K8s** | `cloud-k8s/` | IMDS/IAM, Container Evasion Surface, Kubernetes RBAC |
| **Windows / AD** | `windows-ad/` | Kerberos, AD CS, BloodHound, Relay and Domain Path Evaluation |
| **Digital Forensics** | `digital-forensics/` | Memory/Disk Timeline, PCAP Source Tracing, IR Preservation |
| **Code Audit / SAST** | `code-audit/` | Semgrep/CodeQL, White Box, Dangerous API and Authorization Review |
| **Threat Intelligence / OSINT** | `threat-intelligence/` | Public Sources IOC Supplement, Activity Correlation, Independent Verification and Intelligence Handover |
| **Threat Hunting** | `threat-hunting/` | Hypothesis-Driven Hunting, Sigma Detection Engineering, Blue Team Validation |
| **OT / ICS Industrial Control Systems** | `ot-ics/` | Purdue Segmentation, PLC/SCADA, Passive Prioritization Evaluation |
| **Wi-Fi / Wireless** | `wifi-wireless/` | Authorized Wireless Assessment, Handshake/PMKID, Lab Rules |
| **Browser Extension Reversing** | `browser-extension-reverse/` | Chrome/Firefox Extensions, MV3 Worker, Permissions Face |
| **macOS / Mach-O** | `macos-reverse/` | Signing, ObjC/Swift, LaunchAgent, macOS Samples |
| **Thick Client** | `thick-client/` | Desktop C/S, Local Storage, IPC, Update Channels |
| **Go / Rust Reversing** | `go-rust-reverse/` | Strip Symbols from Go/Rust, pclntab, Panic Strings |
| **Hardware Debugging Interfaces** | `hardware-security/` | UART/JTAG/SWD, Read-Only Extraction, Firmware Handover |
| **Database Security** | `database-security/` | MySQL/PG/MSSQL/Mongo/Redis Exposure and Configuration |
| **Email Security** | `email-security/` | Phishing Disassembly, SPF/DKIM/DMARC, BEC |
| **Federated Identity** | `identity-federation/` | SAML/OIDC/OAuth SSO Flows and Mismatches |
| **RF / SDR** | `radio-sdr/` | Authorized RF Research, Default Reception Only

## Unified Entry

When encountering reverse engineering, CTF, packet capture, frontend signing, APK repackaging, binary analysis tasks, follow this order:

1. Platform native router (Windows `scripts/master-route.ps1`; Linux/macOS/Kali `scripts/master-route.sh`) → PRIMARY (`config/routing.json`)
2. Platform native `case-init` → `scope.md`
3. Open PRIMARY `SKILL.md`
4. When in doubt, read `routing.md`. For local paths, read `tool-index.md`

## Work Philosophy

These modules can be combined as needed:

1. **Get a target** → First check the file type and select the corresponding analysis tool
2. **Quickly find clues** → Use strings / rabin2 -z / ltrace to see if there are any direct leads
3. **Deep analysis** → If decompilation is needed → IDA; if dynamic hooking is needed → Frida; if symbolic execution is needed → angr
4. **If one path doesn't work, try another** → Static analysis fails? Try dynamic. Java layer fails? Check the so. Insufficient page observation? Set breakpoints

## Next-Step Menu Pattern (Next-Step Menu Pattern)

Only when there is a **genuine decision boundary** (two or more materially different, evidence-supported branches exist, and user choice changes the next action) should sub skills provide 3-6 numbered options. If the next step is determined by a gate / Evidence, directly continue and record only `decision_delta` + `carry_forward_refs` in `ops/timeline-workitem.md`; do not re-output unchanged route/scope/auth/context to create a menu.

Format requirements:
- Each option should be numbered (1-6 range)
- Each option should describe a specific executable action (not an abstract direction)
- At least one "export report/write up" option should be included
- At least one "continue deep analysis" or "try another method" option should be included
- Include an "exit/stop/ask other questions" exit when necessary

Example:
```
## Suggested next step (select a number)

1. Deeply decompile sub_140001000 to restore the algorithm
2. Dynamically hook with Frida to verify parameter guesses
3. Export currently named functions and generate symbol migration YAML
4. Generate an analysis report for the current phase
5. Switch to radare2 for lightweight reconnaissance comparison
6. Pause, I need to confirm the previous evidence
```

## Directory is dynamically expanded

This directory will continue to grow. When a new subdirectory is discovered, reading its `SKILL.md` can quickly understand its purpose.

When adding a new skill, follow the standard process in `CONTRIBUTING.md` to ensure:
- The routing matrix correctly分流s
- The bootstrap system automatically补齐 dependencies
- tool-index reflects the status of new tools

## Associated Resources

- There is also **anything-analyzer** (port 23816) MCP server on this machine, providing browser automation, HTTP capture, and AI analysis capabilities
- `tool-index.md` records whether local reverse engineering tools are available, their actual paths, versions, and script references
- The `Readme.md` under the package root provides general installation and integration instructions for Claude Code, Codex CLI, and other code AI clients

## On-demand Bootstrapping

When the workflow discovers missing tools, do not directly report an error. Uniformly call the platform's native bootstrap:

Windows:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill-root>\scripts\bootstrap-reverse.ps1" -Capability @('tool-name') -StartServices
```

Linux / macOS:
```bash
bash <skill-root>/scripts/bootstrap-reverse.sh tool-name --start-services
```

Kali:
```bash
bash <package-root>/kali/scripts/bootstrap-reverse.sh tool-name --start-services
```

Supported capabilities (based on `scripts/bootstrap-manifest.json`): jadx, apktool, jeb-pro, binaryninja, frida, frida-ps, idalib-mcp, reqable-mcp, jshookmcp, xquik-mcp, anything-analyzer, idapro, r2, rabin2, adb, agent-browser, ghidra-mcp, seclists, proxycat, burpsuite-mcp, nmap, pentestswarm, binwalk, yara, pwntools, bkcrack

> JEB Pro has been registered as a **manual license installation** capability: bootstrap only outputs guidance and never downloads or circumvents commercial licensing. Reqable MCP is only registered with the fixed version of the official runtime; users still need to install the Reqable desktop client.
>
> Tools not listed in the manifest (such as unblob/EMBA) `MUST` follow manual installation steps in the skill document, and it is prohibited to pretend they can be bootstrapped.

After bootstrap completes, `tool-index` will automatically refresh.

## Precedent Files Library (Precedent Files)

Before executing any reverse engineering/infiltration operation, MUST read in sequence:

| Read Order | File | When to Read |
|------------|------|--------------|
| **#1**     | `ops/scope-contract.md` + `case-init.ps1` | Authorization gate. Do not write "granted" in `precedent-auth.md` |
| **#2**     | `field-journal/precedent-reverse.md` or `precedent-pentest.md` | On-demand — Load only when AI is indecisive |

**#1 should be read first, #2 can be lazily loaded.**

## Automatic Evolution

After completing a reverse engineering/infiltration task, must write experience back to the `field-journal/` directory. See "Hard Checklist After Task Completion" in `RULES.md`.

- Template: `field-journal/_template.md`
- Index: `field-journal/_index.md`
- Precedents: `field-journal/precedent-auth.md` → `precedent-reverse.md` → `precedent-pentest.md`
- Before starting a new task, check the index and precedents to reuse existing experience

## Task Completion Self-Check (MUST pass before claiming completion)

- [ ] Did I complete the three-axis routing match (target type + user intent + toolchain)?
- [ ] Did I read the target skill's SKILL.md after the route was successful?
- [ ] When the route did not hit, did I propose adding a new skill instead of forcing a match?
- [ ] Did I use real tool paths based on `tool-index`?