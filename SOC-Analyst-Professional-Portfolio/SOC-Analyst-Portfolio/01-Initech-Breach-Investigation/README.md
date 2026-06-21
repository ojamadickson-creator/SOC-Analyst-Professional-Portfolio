# Network Perimeter Breach Investigation

**Organization:** Initech Corp (Simulated Financial Services Firm)  
**Investigation Period:** 37 days (August - September 2025)  
**Total Events Analyzed:** 2,485  
**Final Verdict:** Perimeter Breached - Confirmed

---

## Investigation Overview

This investigation documents the complete analysis of a sustained network perimeter breach at Initech Corp. The adversary maintained unauthorized access for the entire 37-day logging period, establishing persistent command-and-control over an employee workstation via Metasploit port 4444 and exfiltrating data from the internal web application server using HTTP POST uploads.

The attacker exploited stolen VPN credentials for four user accounts, conducted a 118-attempt brute force against a service account in 19 minutes, performed internal lateral scanning across three sensitive hosts, and maintained 80 C2 beacons every six hours for 20 days. The IDS correctly detected all malicious activity and generated Priority 1 alerts, but the overwhelmed SOC team failed to investigate or act. The firewall was misconfigured with a 72.7% allow rate, permitting 87 connections on the Metasploit default port 4444.

**Bottom Line:** The perimeter was breached on Day 1 (August 25) using compromised VPN credentials. The attacker maintained active control until the logs ended on September 30. No remediation was performed during the entire month. The attack was detected but never acted upon due to alert fatigue, missing security controls, and lack of log correlation.

---

## Investigation Phases

### Part A: Command-Line Investigation

| Phase | Title | Description |
|-------|-------|-------------|
| Phase 1 | Initial Log Exploration | Log format reconnaissance, volume assessment, tail analysis |
| Phase 2 | Firewall Log Analysis | Port frequency, ALLOW vs BLOCK ratios, blocked IP analysis |
| Phase 3 | IDS Alert Analysis | C2 beaconing, Metasploit detection, per-asset alert patterns |
| Phase 4 | VPN Authentication Analysis | Brute force detection, compromised account identification |
| Phase 5 | Cross-Correlation & Timeline | Full attack timeline, kill chain reconstruction |

**Screenshots:** All 28 CLI investigation screenshots are available in [02-CLI-Investigation/Screenshots/](02-CLI-Investigation/Screenshots/)

### Part B: Splunk SIEM Investigation

| Phase | Title | Description |
|-------|-------|-------------|
| Phase 6 | Data Validation & Field Discovery | Sourcetype verification, field mapping |
| Phase 7 | IDS Investigation in Splunk | C2 beaconing queries, alert correlation |
| Phase 8 | Firewall Investigation in Splunk | Allowed/blocked traffic analysis |
| Phase 9 | VPN Investigation in Splunk | Brute force and compromised account queries |
| Phase 10 | Cross-Source Correlation | Multi-source SPL correlation across all log types |

---

## Key Findings

### Finding 1: Perimeter Breach Confirmed on Day 1
The attacker had valid VPN credentials for at least four accounts (alice, bob, svc_backup, jsmith) starting August 25, 2025. The first successful VPN login from attacker IP 203.0.113.45 occurred at 08:25:10 on August 25. The "new firewall and IDS" deployment did not cause the breach - it merely provided visibility into an already-compromised environment.

### Finding 2: Service Account Brute Force Successful
On September 3, 2025, the attacker conducted an automated brute force against svc_backup, making 118 failed attempts at 10-second intervals over 19 minutes before succeeding. No account lockout policy was in place. After success, svc_backup was assigned VPN IP 10.8.0.23.

### Finding 3: Lateral Movement Across Three Critical Hosts
On September 5, 2025, the VPN attacker (10.8.0.23) conducted a 15-hour internal network scan targeting APP-WEB-01, WORKSTATION-60, and FINANCE-SRV1 on ports 22 (SSH), 445 (SMB), and 3389 (RDP). Of 90 total connection attempts, approximately 67% were ALLOWED by the firewall.

### Finding 4: Persistent C2 for 20 Days
Starting September 11, 2025, WORKSTATION-60 established 80 reverse shell beacons to 198.51.100.77:4444, occurring every 6 hours with clockwork precision. The IDS correctly identified each beacon as ET TROJAN Possible C2 Beaconing with Priority 1 classification. The firewall allowed all 80 outbound C2 connections.

### Finding 5: Data Exfiltration Confirmed
Beginning September 27, 2025, APP-WEB-01 initiated 60 HTTP POST uploads to 198.51.100.77:80 (32) and 198.51.100.77:8080 (28). The IDS explicitly classified this traffic as Potential Data Exfiltration via the ET INFO Possible HTTP POST Large Upload signature.

### Finding 6: No Remediation Performed
The final C2 beacon occurred on September 30, 2025 at 19:00:00 - the exact moment the logs ended. No detection, containment, or remediation actions were taken during the entire 37-day incident window. The attacker maintained uninterrupted access throughout.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Evidence |
|--------------|----------------|--------|----------|
| T1078 | Valid Accounts | Initial Access | Compromised VPN credentials (alice, bob, jsmith, svc_backup) |
| T1110 | Brute Force | Credential Access | 118 failed attempts on svc_backup in 19 minutes |
| T1110.001 | Password Guessing | Credential Access | Automated login attempts at 10-second intervals |
| T1021 | Remote Services | Lateral Movement | RDP (port 3389), SSH (port 22), SMB (port 445) scanning |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | Connections to port 3389 from 10.8.0.23 |
| T1021.004 | SSH | Lateral Movement | Connections to port 22 from 10.8.0.23 |
| T1071 | Application Layer Protocol | Command and Control | HTTP-based C2 communication on ports 80, 8080 |
| T1071.001 | Web Protocols | Command and Control | HTTP POST uploads for data exfiltration |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Data uploaded to 198.51.100.77:80 and :8080 |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | HTTP POST large uploads (60 events) |
| T1001 | Data Obfuscation | Command and Control | Ephemeral source ports on C2 beacons |
| T1036 | Masquerading | Defense Evasion | C2 traffic on common HTTP ports (80, 8080) to blend in |
| T1567 | Exfiltration Over Web Service | Exfiltration | HTTP POST uploads to external attacker-controlled server |
| T1083 | File and Directory Discovery | Discovery | Lateral scanning suggests internal reconnaissance |

---

## Root Cause Analysis

| Control | Status | Failure Impact |
|---------|--------|---------------|
| Account Lockout Policy | Missing | 118 brute force attempts succeeded |
| MFA on VPN | Missing | Compromised password = instant access |
| Geo-IP Restrictions | Missing | Attacker rotated IPs freely |
| Egress Filtering | Missing | C2 traffic outbound on 4444, 80, 8080 |
| Network Segmentation | Missing | VPN clients reached internal LAN directly |
| IDS Alert Triage | Failed | 80 Priority 1 alerts ignored for 20 days |
| Service Account Governance | Missing | svc_backup had VPN access |
| Firewall Policy | Misconfigured | 72.7% allow rate, port 4444 open |
| Log Correlation | Missing | VPN + firewall + IDS never cross-referenced |
| Password Policy | Weak | svc_backup cracked in under 20 minutes |

---

## Artifacts

- **Screenshots:** 28 CLI investigation screenshots in [02-CLI-Investigation/Screenshots/](02-CLI-Investigation/Screenshots/)
- **Full Report:** [Initech-Incident-Response-Report.pdf](06-Reports/Initech-Incident-Response-Report.pdf) (45 pages)

---

## Quick Stats

- **Firewall Events:** 1,284
- **IDS Alerts:** 983
- **VPN Records:** 218
- **Blocked Connections:** 351 (27.3%)
- **Allowed Connections:** 933 (72.7%)
- **Compromised Accounts:** 4 (alice, bob, jsmith, svc_backup)
- **C2 Beacons:** 80 over 20 days
- **MITRE Techniques Mapped:** 14 across 7 tactics
