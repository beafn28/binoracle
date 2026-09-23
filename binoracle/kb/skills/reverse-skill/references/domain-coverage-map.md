# Domain Coverage Map (Depth-First)

> In line with the community's "hundreds of micro skills": We use **a few deep skills + routing + ops** to cover the main battlefield.  
> Date: 2026-07-18

## Domain → Package Entry

| Domain | PRIMARY / Module | Remarks |
|--------|------------------|---------|
| Mobile Android | `apk-reverse/` `mobile-reverse/` | |
| Mobile iOS | `mobile-reverse/` | |
| Binary Deep Dive | `ida-reverse/` `radare2/` `ghidra-reverse/` | Ghidra = Open-source main path |
| General RE / Anti-Debugging / OLLVM | `reverse-engineering/` | |
| .NET | `dotnet-reverse/` | |
| Frontend JS / Signing | `js-reverse/` | |
| Browser Extensions | `browser-extension-reverse/` | |
| DSL/Risk VM | `reverse-engineering/dsl-vm-reverse/` | |
| Protocol / PCAP Protocol | `protocol-reverse/` | |
| Firmware IoT | `firmware-pentest/` | |
| Malware Samples | `malware-analysis/` | |
| Digital Forensics / IR | `digital-forensics/` | |
| Threat Hunting / Blue Team | `threat-hunting/` | |
| Penetration Tools | `pentest-tools/` (+ src-hunter) | |
| Windows / AD | `windows-ad/` | |
| Cloud / Containers / K8s | `cloud-k8s/` | |
| Code Audit / SAST | `code-audit/` | |
| Wi-Fi / Wireless | `wifi-wireless/` | |
| OT / ICS | `ot-ics/` | Passive first; register writes default disabled |
| macOS | `macos-reverse/` | iOS still goes to mobile-reverse |
| Binary Ninja | `binary-ninja-reverse/` | Commercial GUI/Python API; community MCP only explicitly enabled and default loopback binding |
| Thick Client | `thick-client/` | |
| Go / Rust Binaries | `go-rust-reverse/` | |
| Hardware Debug Port | `hardware-security/` | Handover to firmware-pentest |
| Database | `database-security/` | |
| Email / Phishing | `email-security/` | |
| Federated Identity SSO | `identity-federation/` | Complementary to api-security JWT |
| RF / SDR | `radio-sdr/` | Default receive only; non-Wi-Fi |
| Multi-Stage Attacks | `attack-chain/` | |
| Pwn | `pwn-chain/` | |
| N-day Patch | `patch-diff-exploit/` | |
| EDR Research | `edr-bypass-re/` | |
| API | `api-security/` | |
| Supply Chain SBOM | `supply-chain-security/` | |
| LLM/Agent | `llm-security/` | + `ops/skill-supply-chain.md` |
| Browser Automation | `browser-automation/` | |
| Reports/Charts | `docs-generator/` `diagram-generator/` | |
| Symbol Migration | `binary-diff/` | |
| Operational Contracts | `ops/` | **Special Feature** |
| CTF Orchestration | `CTF-Sandbox-Orchestrator/` | |
| Cryptography Mode Recognition | `reverse-engineering` mode documentation | Shared with reverse engineering tasks, no independent extension package maintained |

## Domains Not Included in the Package (Strategy When Routing Misses)

| Domain | Strategy |
|--------|----------|
| Pure Game Cheating Development | Not as a product direction; Unity samples can still go to `reverse-engineering` + seed-014 |
| Deep Automotive/Aerospace Certification-Level | Can be linked externally; this package has only RF/OT entry-level |
| Pure GRC/Compliance Long Articles | Do not replace professional GRC tools; can write report template references |
| 800+ ATT&CK Micro Skills | Use this table + optional ATT&CK labels (Finding field) |

## With MITRE ATT&CK (Optional)

The Finding template allows `optional_attack: Txxxx` (see `ops/evidence-finding-path.md`). **Not mandatory** to use the full ATT&CK engine.