# Community Security Skill Ecosystem (2026-07)

> Source Retrieval Date: **2026-07-17**  
> Purpose: Let reverse-skill **know what's outside**, borrow as needed, **not** merge entire external large libraries into this package.  
> This Package Identity: Router + Tool Bootstrap + Evidence/Scope Contract + Field-Journal (see `ops/IDENTITY.md`).

## 1. External High-Value Repositories (Learnable, Do Not Blind Install)

| Repository | Scale/Locality | Value to This Package | Risk |
|------------|----------------|-----------------------|------|
| [trailofbits/skills](https://github.com/trailofbits/skills) | ToB Security Research Claude Plugin Market | Audit/Vulnerability Analysis/RE Plugin Quality Benchmark | Needs installation for the ToB market; do not trust non-curated copies by default |
| [trailofbits/skills-curated](https://github.com/trailofbits/skills-curated) | List of Reviewed Plugins | Prioritize over any community skill | Same as above |
| [Orizon-eu/claude-code-pentest](https://github.com/Orizon-eu/claude-code-pentest) | 6 Pentest Lifecycle Skills + Pure Python Scripts | Recon→Exploit→Report Pipeline Comparable to Our `attack-chain`+`pentest-tools` | Self-inspect authorization boundaries; scripts need sandboxing |
| [trilwu/secskills](https://github.com/trilwu/secskills) | 16 Skills + 6 Expert Subagents | Multi-Role Division Comparable to `ops/role-map.md` | Plugin Form, Different from This Package Monorepo |
| [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) | ~15–19 Domain Skills (Including RE/OT/CSOC) | Domain Coverage Checklist | Depth Not as Deep as Single-Domain Skills in This Package |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | **800+** Skills · ATT&CK/NIST Mapping | **Framework Mapping** and Domain Directory Reference, Not Suitable for Full Library Dependency | Large Volume, Maintenance and Poisoning Surface Too Big |
| [Eyadkelleh/awesome-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security) | SecLists Packaged as Agent Skills | Dictionary/Payload Entry | Overlaps with `seclists` Bootstrap |
| [securityfortech/awesome-security-skills](https://github.com/securityfortech/awesome-security-skills) | Selected List of Security Skills | Index for Discovering New Skills | List Type, Needs Individual Auditing |
| [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) | 1000+ Cross-Vendor Skill Index | Discovery of Official/Community Skills | Not Security-Specific |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | PR Security Review GitHub Action | Comparable to Our `docs/` Report Side «Change Audit» Scenario | CI Product, Not an RE Router |
| [agentskills.io](https://agentskills.io) | Agent Skills Open Standard | Frontmatter/Directory Conventions Alignment | Standard Itself Has No Offense-Defense Content |

### 1.1 Second Round Retrieval Supplement (2026-07-17 Re-search)

| Repository / Resource | Locality | This Package Landing |
|-----------------------|----------|----------------------|
| [trailofbits/skills](https://github.com/trailofbits/skills) Plugins: `audit-context-building` `differential-review` `semgrep-rule-creator` `sharp-edges` `dwarf-expert` `burpsuite-project-parser` | Audit Context, Differential Security Review, Dangerous API, DWARF, Burp Project Parsing | Align with `ida-reverse`/`docs-generator`/Audit Workflow; **not** merge entire library |
| [HexRaysSA/ida-claude-code-plugins](https://github.com/HexRaysSA/ida-claude-code-plugins) | Official IDA Claude Plugins (Includes Domain Automation, Marking Unsafe Code) | `ida-reverse` MCP Path Alignment; Unsafe Plugins Default Not Enabled |
| [P4nda0s/reverse-skills](https://github.com/P4nda0s/reverse-skills) | IDA-NO-MCP: Export Disassembly Then Analyze; rev-frida/dex-dump/u3d | Complementary to «Offline Export When MCP Unavailable» |
| [2389-research/binary-re](https://github.com/2389-research/binary-re) | Triage→Static(r2/Ghidra)→Dynamic(QEMU/GDB/Frida)→Synthesis | `reverse-engineering` Phase Gate See `re-agent-workflow.md` |
| [incogbyte/android-reverse-engineering-claude-skill](https://github.com/incogbyte/android-reverse-engineering-claude-skill) | APK Unpacking, Endpoint Extraction, Adaptive Frida Bypass | Align with `apk-reverse`; Dynamic Scripts Need Scope |
| [OwenPawl/cerberus-re-skill](https://github.com/OwenPawl/cerberus-re-skill) | Apple to Ghidra+LLDB+Frida Three Loops | Reference macOS/iOS Dynamic Environment |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | CTF Reverse/Pwn; Tools Installed As Needed | Align with CTF-Sandbox + `pwn-chain` |
| [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) | /recon→/hunt→/validate→/report | Align with `recon-pipeline.md` + Scope Gate |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Web Payloads + Prompt Injection Chapter | `pentest-tools/payloads` Priority; LLM See `llm-security` |
| [HackTricks](https://hacktricks.wiki/) | Penetration Methodology + **AI/MCP Abuse** | See Skill-Supply-Chain MCP Section |
| [appsecsanta AI pentesting agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026) | 39+ Open Source AI Penetration Agent Architecture Classification | Multiple Agents ≠ Must; We Use Role-Map |
| Snyk Evaluation «More Skills ≠ Better» | Skill Stacking May Lower Audit Quality | Strengthen «Deep Skills + Routing» Strategy |



## 2. Security Standards and Threats (2025–2026)

| Source | Key Points | Package Landing Point |
|------|------|----------|
| [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) | Malicious skills, supply chain attacks, privilege escalation, memory poisoning, etc. | `ops/skill-supply-chain.md` |
| [Anthropic Agent Skills Engineering Document](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) | Only install from trusted sources; review scripts and dependencies | Same + bootstrap to prevent guessing paths |
| ClawHavoc and other poisoning activities (AST10 recorded) | Batch malicious skills in the registry | Prohibit one-click installation of unknown registry entries into this package |

## 3. Existing in This Package vs External 'Wide' Coverage

| Domain | reverse-skill | Reasons for not integrating external libraries |
|------|---------------|--------------------------------|
| APK/JS/IDA/r2/Firmware/Pwn | **Deep** skills + scripts | Maintain depth and binding with tool-index |
| Penetration/Attack Chain/SRC | pentest-tools + attack-chain + src-hunter | Orizon-like methods for methodological comparison |
| LLM/Agent Security | llm-security | AST10 to enhance skill self-security |
| Evidence/Scope/Roles | **ops/** (special) | Most skill packages lack case contracts |
| OT/ICS / Pure GRC / Fraud F3 | No independent skills | Route not hit → Suggest adding or linking externally, do not force |
| Over 800 micro-skills | Do not copy | Replace fragmented skills with MASTER routing + domain skills |

## 4. Guidelines (MUST)

```text
1. Prohibit pulling a library of over 800 skills as a git submodule when running-time dependencies are required.
2. When borrowing: Extract 'stage/list/command pattern' and write to this package's references or existing skills.
3. External scripts: First test dependencies and network behavior in an isolated environment, then consider bootstrap-manifest.
4. New scenarios: Follow CONTRIBUTING to add new skills, update routing + RULES keywords.
5. Annotate source URL + retrieval date (this file format).
6. Before installation/merging, follow the ops/skill-supply-chain.md list.
7. Only load PRIMARY (plus necessary secondary) from MASTER-ROUTING at runtime to avoid skill overload.
```

## 4.1沉淀的「借鉴产物」（非外库依赖）

| Product | Path |
|------|------|
| RE 四阶段 | `reverse-engineering/references/re-agent-workflow.md` |
| 授权侦察 | `pentest-tools/references/recon-pipeline.md` |
| 攻击链门闩 | `attack-chain/references/lifecycle-checklist.md` |
| Skill 供应链 | `ops/skill-supply-chain.md` |
| 领域覆盖 | `references/domain-coverage-map.md` |

## 5. Suggested Priorities (for subsequent iterations)

| Priority | Action |
|--------|------|
| P0 Done | ops contracts, MASTER routing, skill supply chain security documents |
| P1 | Align Orizon/ToB pentest checklists to attack-chain references |
| P2 | Optional 'external skill whitelist' configuration, do not enter default paths |