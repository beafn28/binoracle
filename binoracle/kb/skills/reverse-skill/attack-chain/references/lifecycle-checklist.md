# Penetration/Attack Chain Lifecycle Checklist

> Compare with the community pentest skill package (e.g., Orizon claude-code-pentest six-stage) and integrate this package's `attack-chain` + `ops`.  
> Inspiration source: Public Claude pentest lifecycle skills (2026-07 retrieval); **commands and authorization are based on this package's scope**.  
> Date: 2026-07-17

## Before Use

- [ ] `case-init` completed, `auth.status=granted`
- [ ] `network_profile` ≠误用 unrestricted for production
- [ ] `lead` has specified specialist_roles (`ops/role-map.md`)

## Stage Gateways

| Stage | Role | Package Skill | Completion Criteria |
|-------|------|---------------|---------------------|
| 0 Scope | lead | ops/scope-contract | ready_for_act |
| 1 Recon | cie | pentest-tools | assets list + timeline |
| 2 Enum/Vuln | cpe | pentest-tools / api-security | draft F-* |
| 3 Validate | cpe | pentest-tools | E-* + validated Finding |
| 4 Post-ex（若授权） | cpe/lead | attack-chain 后半 | 不超 out_of_scope |
| 5 RE 辅助 | cre | ida/apk/js/… | 仅当需要客户端/二进制 |
| 6 Report | doc | docs-generator | Evidence→Finding→Path |
| 7 Journal | lead | field-journal | 脱敏 |

## Differences from 'Automate Breaking Through a Domain Name Fully' Class Skills (Features)

| Common in External Automation Packages | Reverse-Skill |
|----------------------------------------|---------------|
| Default to sweeping domains wildly      | Must scope asset list |
| Weak evidence directly writing reports  | Force E/F/P chain |
| Single session without roles            | role-map handover |
| No tool index                         | tool-index + bootstrap |

## At least one timeline item per stage

Format see `ops/timeline-workitem.md`.