---
name: code-audit
description: Use for authorized source-code security review and SAST workflows including Semgrep, CodeQL patterns, dangerous API hunting, and fix verification.
---

# Source Code Security Audit

## ACTION REQUIRED（Read this immediately）

1. `NOW`: Read `../field-journal/precedent-pentest.md` or code audit authorization
2. `NOW`: Confirm you have **source code/repository access** (no source code binary → switch to RE skill)
3. `NOW`: Clarify the language stack and scope (directory/service/PR diff)
4. `NEXT`: tool-index; semgrep, etc.
5. `ACT`: Threat modeling sketch → automated scan → manual verification

## Applicable Scenarios

- White-box audit, PR/diff security review
- Semgrep / CodeQL / Bandit / gosec, etc. SAST
- Dangerous APIs, injection points, authentication missing, encryption misuse
- With `supply-chain-security/` division: This skill focuses on **own code logic**, supply chain focuses on dependencies and pipelines

## Workflow

### 1. Scope and Threat Model

```text
□ Trust boundary: user input, files, deserialization, SSRF, auth middleware
□ High-value assets: auth, payment, management console, key handling
```

### 2. Automated Scanning

```bash
semgrep --config auto .
# or project rule pack
semgrep --config p/owasp-top-ten .
```

### 3. Manual Verification (MUST)

```text
□ Each SAST hit: reachable? exploitable? false positive?
□ Auth: IDOR/privilege escalation, missing validation, incorrect multi-tenant isolation
□ Injection: SQL/command/template/LDAP
□ Encryption: hard-coded keys, ECB, custom crypto
```

### 4. Output

```text
Finding: location + data flow + PoC + fix recommendation
Optional ATT&CK / CWE IDs
```

## Toolchain

| Tool | Language/Scenario |
|------|-----------------|
| Semgrep | Multi-language quick rules |
| CodeQL | Deep data flow (GitHub) |
| Bandit | Python |
| gosec / staticcheck | Go |
| SpotBugs / FindSecBugs | Java |

## References

- `references/sast-review-checklist.md`
- `../supply-chain-security/` `../api-security/` `../llm-security/` (Agent code)

## Routing Context

**Upstream**: MASTER R26  
**Role**: `ops/role-map.md` cae  
**Downstream**: Dependency vulnerabilities → supply-chain; runtime verification → pentest-tools

## Task Completion Self-Check

- [ ] Is manual verification included instead of just pasting scanner output?
- [ ] Does it include fix recommendations?
- [ ] Is it limited to authorized repository scope?
- [ ] Checklist?