# SOC Analyst Portfolio

A collection of hands-on cybersecurity investigations, incident response case studies, and threat detection projects. Each project documents real-world SOC workflows using industry-standard tools and frameworks.

---

## Featured Project: Network Perimeter Breach Investigation

**Type:** SOC Level 1 Incident Response Investigation  
**Platform:** TryHackMe - Network Security Essentials  
**Date:** TryHackMe, 2026  
**Status:** Completed

### Overview

A full forensic investigation of a sustained network perimeter breach at Initech Corp, a simulated financial services firm. The attacker maintained unauthorized access for **37 days**, establishing persistent command-and-control over an employee workstation and exfiltrating data from the internal web application server.

The investigation employed both **command-line forensics** (Linux CLI) and **Splunk SIEM analysis** to correlate **2,485 events** across three independent log sources: firewall logs, IDS alerts, and VPN authentication records.

### What I Did

- Analyzed **2,485 security events** using Linux CLI pipelines (grep, awk, cut, sort, uniq) and Splunk SPL queries
- Identified **port 4444 (Metasploit default)** as the primary attack vector with **87 of 127 connections allowed** by the firewall
- Discovered a **118-attempt brute force** against the `svc_backup` VPN account with **no account lockout policy**
- Mapped **lateral movement** across three critical internal hosts (finance server, web app server, workstation)
- Detected **80 C2 beacons every 6 hours for 20 days** - textbook Meterpreter behavior
- Uncovered **60 HTTP POST upload events** indicating confirmed data exfiltration
- Built **5 production-ready Splunk detection rules** with threshold-based alerting
- Mapped **14 MITRE ATT&CK techniques** across 7 tactics
- Authored a **45-page incident response report** with executive summary, timeline, root cause analysis, and remediation steps

### Tools & Technologies

| Category | Tools |
|----------|-------|
| SIEM | Splunk Enterprise |
| CLI Forensics | Linux Bash (grep, awk, cut, sort, uniq, head, tail, wc) |
| IDS/IPS | Snort / Suricata |
| Visualization | Python (matplotlib) |
| Frameworks | MITRE ATT&CK, NIST SP 800-53, NIST SP 800-61, PCI DSS |

### Repository Structure

```
01-Initech-Breach-Investigation/
├── 02-CLI-Investigation/           # Command-line forensics (Phases 1-5)
│   └── Screenshots/                # 28 investigation screenshots
├── 03-Splunk-Investigation/        # SIEM analysis (Phases 6-10)
│   └── Screenshots/
├── 04-Key-Findings/                # MITRE mapping, root cause, evidence
├── 05-Detection-Rules/             # Splunk SPL detection rules
└── 06-Reports/                     # Full PDF incident response report
```

### Key Findings at a Glance

| Finding | Detail |
|---------|--------|
| Perimeter Breach | Day 1 (August 25) via compromised VPN credentials |
| Brute Force | 118 attempts on `svc_backup` in 19 minutes - no lockout |
| Lateral Movement | 15-hour scan of 3 hosts on ports 22, 445, 3389 |
| C2 Beaconing | 80 beacons every 6 hours for 20 days |
| Data Exfiltration | 60 HTTP POST uploads on ports 80/8080 |
| Firewall Misconfig | 72.7% allow rate, port 4444 open |
| MITRE Techniques | 14 techniques across 7 tactics |

[View Full Investigation Details](01-Initech-Breach-Investigation/README.md)

---

## Project 2: SOC Alert Triage Simulation

**Type:** SOC Alert Triage & Incident Investigation  
**Platform:** TryHackMe - SOC Simulator  
**Date:** TryHackMe, 2026  
**Status:** Completed

Triaged 36 alerts in a simulated SOC environment, achieving **100% true positive detection**. Investigated a targeted CEO spear-phishing attack, tracing the full kill chain from initial email delivery through PowerView/PowerUp exploitation to data exfiltration via Robocopy.

[View Details](02-SOC-Alert-Triage-Simulation/README.md)

---

## About Me

SOC Analyst with a solid foundation in threat detection, incident response, and log analysis. CompTIA Security+, Network+, A+, and CSIS certified. Based in Almada, Portugal.

- **LinkedIn:** [linkedin.com/in/ojama-d-28a13814a](https://linkedin.com/in/ojama-d-28a13814a)
- **Email:** ojamadickson@gmail.com
