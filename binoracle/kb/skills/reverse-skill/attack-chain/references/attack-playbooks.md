# Attack Chain Playbook Quick Reference

> Select the corresponding playbook based on the target type. Each playbook defines a standard path from initial access to achieving the objective.

---

## Playbook 1: External Web App → Domain Controller

```
1. Subdomain enumeration + port scanning
2. Web fingerprinting → identify known vulnerable components
3. Exploit vulnerabilities to get Webshell / RCE
4. Internal information collection (ipconfig/ifconfig, arp, net user)
5. Establish a tunnel (frp/chisel/ssh)
6. Internal network scanning (alive hosts, open ports)
7. Credential acquisition (mimikatz/hashdump/config files)
8. Lateral movement (PTH/WMI/PsExec)
9. Domain information collection (BloodHound)
10. Domain privilege escalation (Kerberoasting/DCSync/constrained delegation)
11. Gain domain controller privileges
```

**Key Toolchain**: subfinder → httpx → nuclei → sqlmap/sstimap → frp → nmap → mimikatz → crackmapexec → bloodhound → certipy

---

## Playbook 2: Phishing → Internal Penetration

```
1. Target employee information collection (LinkedIn/WeChat)
2. Construct phishing emails (fake sender/legitimate subject)
3. Create payloads (macro documents/LNK/ISO/HTML smuggling)
4. Send phishing emails
5. Wait for compromise (C2 beacon)
6. Local information collection + privilege escalation
7. Credential extraction
8. Lateral movement
9. Persistence
10. Objective achieved
```

**Key Toolchain**: theHarvester → gophish → msfvenom/cobalt-strike → mimikatz → bloodhound

---

## Playbook 3: Source-Based Penetration → Internal Network

```
1. Physical reconnaissance (WiFi signal, access control type, USB ports)
2. WiFi attack (Fluxion fake hotspot / WPA cracking)
   or BadUSB implant (Rubber Ducky keyboard injection)
   or network implant (Raspberry Pi / LAN Turtle)
3. Get internal access point
4. Internal network scanning
5. Subsequent steps 5-11 from Playbook 1
```

**Key Toolchain**: fluxion/aircrack-ng → rubber-ducky → frp → nmap → crackmapexec

---

## Playbook 4: Cloud Environment Penetration

```
1. Cloud asset discovery (subdomain → CNAME → cloud service provider)
2. Bucket enumeration (S3/OSS/Blob public access)
3. SSRF → cloud metadata (169.254.169.254)
4. Get temporary credentials (AK/SK/Token)
5. Cloud API enumeration (IAM/EC2/Lambda/RDS)
6. Privilege escalation (PassRole/AssumeRole)
7. Lateral movement (cross-account/cross-region)
8. Data retrieval
```

**Key Toolchain**: subfinder → nuclei(ssrf) → aws-cli → pacu → ScoutSuite

---

## Playbook 5: Bug Bounty / SRC Quick Scanning

```
1. Asset collection (subdomain + ports + JS files)
2. Fingerprinting → quick validation of known vulnerabilities (nuclei)
3. Parameter discovery (arjun/paramspider)
4. Class-based testing:
   - IDOR/privilege escalation (change ID/change role)
   - SSRF (internal probing/cloud metadata)
   - SQL injection (sqlmap)
   - XSS (xsstrike)
   - File upload (bypass detection)
   - Logical vulnerabilities (payment/captcha/password reset)
5. Write PoC + submit report
```

**Key Toolchain**: subfinder → httpx → nuclei → arjun → sqlmap → xsstrike → burpsuite

---

## Playbook 6: AD CS Certificate Attack

```
1. Discover AD CS service (certipy find)
2. Identify vulnerable templates (ESC1-ESC8)
3. Request malicious certificate
4. Use the certificate for authentication as target user
5. Get NTLM Hash or TGT
6. DCSync export all credentials
```

**Key Toolchain**: certipy → rubeus → mimikatz → secretsdump

---

## General Decision Matrix

| Current State | Next Step Priority |
|---------------|---------------------|
| Only target domain | Subdomain enumeration → port scanning → Web fingerprinting |
| Web vulnerabilities identified | Get shell → internal information collection |
| Low-privilege shell obtained | Privilege escalation → credential extraction |
| One internal machine compromised | Establish tunnel → internal network scanning → lateral movement |
| Domain user credentials obtained | BloodHound → find attack path |
| Domain admin hash obtained | DCSync → Golden Ticket |
| Cloud AK/SK obtained | Enumerate permissions → privilege escalation → data retrieval |
| Phishing compromise achieved | Local privilege escalation → credential extraction → lateral movement |
| Near-source access gained | Internal network scanning → same as above |