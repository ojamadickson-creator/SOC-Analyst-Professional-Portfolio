# How to Feature the Initech Breach Investigation on Your CV

This guide shows you how to transform your incident response project into a powerful CV asset that gets past ATS filters, impresses recruiters, and wins interviews.

---

## 1. Where to Place the Project on Your CV

### Option A: Dedicated "Projects" Section (Recommended for Entry-Level)

Best if you have limited professional experience. Place it prominently after your Skills section and before Education.

### Option B: Within "Professional Experience" (Recommended if You Have Some Experience)

Frame it as a freelance/consulting engagement:

> **Cybersecurity Incident Response Analyst** | Personal Portfolio Project  
> *Jan 2025 – Present*

### Option C: Hybrid Approach (Best for Career Changers)

Create a "Technical Projects & Case Studies" section that sits between Work Experience and Education.

---

## 2. The Project Title That Gets Clicks

| Weak Title | Strong Title |
|-----------|-------------|
| "Network Security Project" | **"SOC Level 1 Incident Response: Multi-Source Log Analysis of a Sustained Network Perimeter Breach"** |
| "Splunk Project" | **"Digital Forensics Investigation: Command-Line & SIEM Analysis of a 37-Day APT-Style Intrusion"** |
| "Firewall Log Analysis" | **"Enterprise Security Assessment: Correlating 2,485 Events Across Firewall, IDS, and VPN Logs to Map a Full Kill Chain"** |

**Pro Tip:** Use keywords from actual job postings. Search LinkedIn for "SOC Analyst" or "Incident Response Analyst" roles and mirror their language.

---

## 3. The Bullet Points That Sell (Copy-Paste Ready)

### For a SOC Analyst / Blue Team Role:

```
SOC Level 1 Incident Response – Network Perimeter Breach Investigation

• Conducted end-to-end forensic investigation of a sustained network intrusion, analyzing 2,485 events
  across firewall, IDS, and VPN authentication logs using Linux CLI tools and Splunk SIEM

• Identified a 37-day APT-style attack chain spanning initial access (compromised VPN credentials),
  lateral movement (internal reconnaissance), persistent C2 beaconing (80 confirmed beacons), and
  confirmed data exfiltration via HTTP POST uploads

• Mapped attacker infrastructure including 7 external IPs, 4 compromised user accounts, and a
  dedicated C2 server (198.51.100.77) using cross-source log correlation

• Discovered a credential brute-force attack (118 attempts in 19 minutes) against a service account
  and traced the attacker's VPN IP assignment (10.8.0.23) to subsequent internal scanning activity

• Quantified firewall misconfiguration revealing a 72.7% allow rate and 87 permitted connections
  on Metasploit's default port (4444), violating NIST SP 800-53 default-deny principles

• Built 5 Splunk detection rules (SPL) for real-time alerting on C2 beaconing, data exfiltration,
  VPN brute force, lateral movement, and multi-IP account compromise

• Documented findings in a 45-page professional incident response report with MITRE ATT&CK
  mapping (14 techniques), root cause analysis, and actionable remediation recommendations
```

### For a Splunk/SIEM Analyst Role:

```
Splunk SIEM Investigation – Multi-Source Security Event Correlation

• Analyzed 2,485 security events across three independent data sources (firewall, IDS, VPN) using
  Splunk SPL queries to reconstruct a 37-day attack timeline

• Wrote 25+ SPL queries utilizing stats, eval, timechart, fieldsummary, and regex extraction to
  identify C2 beaconing (80 events), data exfiltration (60 events), and lateral movement (90 events)

• Built a cross-source correlation query joining firewall_logs, ids_logs, and vpn_logs sourcetypes
  to classify events into 5 attack phases and calculate phase distribution percentages

• Validated data quality using fieldsummary and head commands before hunting, ensuring accurate
  field extraction across JSON-formatted sourcetypes

• Created 5 Splunk saved searches with threshold-based alerting for C2 detection, exfiltration
  monitoring, brute-force identification, lateral movement detection, and compromised account flags
```

### For a Digital Forensics / Incident Response Role:

```
Digital Forensics Case Study – Enterprise Network Intrusion Analysis

• Performed forensic analysis of firewall, IDS (Snort/Suricata), and VPN authentication logs to
  investigate a confirmed network perimeter breach at a financial services organization

• Established evidence chain: external attacker IP (203.0.113.45) → compromised VPN account
  (svc_backup) → assigned internal IP (10.8.0.23) → lateral scan (3 hosts, 3 ports, 90 connections)

• Identified 80 C2 beaconing events with clockwork precision (every 6 hours, 20 days) using
  sequential ephemeral port analysis (30000–30079), consistent with Meterpreter behavior

• Confirmed data exfiltration via IDS signatures ("HTTP POST Large Upload" with classification
  "Potential Data Exfiltration") from APP-WEB-01 to attacker-controlled server on ports 80/8080

• Mapped 14 MITRE ATT&CK techniques across 7 tactics including Initial Access (T1078, T1133),
  Lateral Movement (T1021.001, T1021.002), C2 (T1071.001, T1571), and Exfiltration (T1041)

• Produced a 45-page incident response report with executive summary, timeline reconstruction,
  root cause analysis (10 failed controls), and 13 prioritized remediation recommendations
```

---

## 4. Skills Section Keywords to Include

Add these to your Skills section so ATS systems flag your CV:

**Technical Skills:**
```
Splunk SPL | SIEM Analysis | Log Correlation | Digital Forensics | Incident Response
Linux CLI (grep, awk, sed, cut, sort, uniq) | Firewall Analysis | IDS/IPS (Snort/Suricata)
VPN Security | MITRE ATT&CK Framework | Network Perimeter Security | C2 Detection
Data Exfiltration Analysis | Lateral Movement Detection | Credential Compromise Investigation
```

**Tools:**
```
Splunk Enterprise | Linux Terminal | Wireshark (implied) | Python (for chart generation)
```

**Frameworks & Standards:**
```
MITRE ATT&CK | NIST SP 800-53 | NIST SP 800-61 (IR) | PCI DSS
```

---

## 5. Quantification Guide (The Numbers That Matter)

Recruiters scan for numbers. Make sure these appear prominently:

| Metric | Why It Matters |
|--------|---------------|
 **2,485 events analyzed** | Shows scale of investigation |
| **37-day attack window** | Demonstrates persistence detection |
| **80 C2 beacons** | Proves sustained monitoring capability |
| **118 brute-force attempts** | Shows attention to credential security |
| **7 external attacker IPs** | Demonstrates infrastructure mapping |
| **4 compromised accounts** | Proves scope assessment |
| **72.7% firewall allow rate** | Shows policy analysis skills |
| **5 Splunk detection rules** | Demonstrates proactive defense |
| **45-page report** | Shows documentation professionalism |
| **14 MITRE techniques mapped** | Proves framework competency |

---

## 6. GitHub/GitLab Portfolio Strategy

### Create a Public Repository:

```
Repository Name: network-perimeter-breach-investigation
Description: SOC Level 1 incident response case study analyzing a sustained network intrusion
             using Linux CLI forensics and Splunk SIEM correlation
```

### Repository Structure:
```
📁 network-perimeter-breach-investigation/
├── 📄 README.md                          ← Overview + key findings
├── 📄 INCIDENT-REPORT.pdf                ← Your 45-page portfolio (this PDF)
├── 📁 splunk-queries/
│   ├── 01-data-validation.spl
│   ├── 02-ids-c2-detection.spl
│   ├── 03-firewall-analysis.spl
│   ├── 04-vpn-brute-force.spl
│   └── 05-cross-correlation.spl
├── 📁 cli-commands/
│   ├── 01-log-exploration.sh
│   ├── 02-firewall-analysis.sh
│   ├── 03-ids-analysis.sh
│   ├── 04-vpn-analysis.sh
│   └── 05-timeline-correlation.sh
├── 📁 mitre-mapping/
│   └── attck-techniques.md
├── 📁 detection-rules/
│   └── splunk-saved-searches.md
└── 📁 visualizations/
    ├── attack-phase-distribution.png
    ├── c2-beaconing-timeline.png
    ├── vpn-brute-force.png
    └── killchain-timeline.png
```

### README.md Template (Copy-Paste):

```markdown
# Network Perimeter Breach Investigation

**Role:** SOC Level 1 Incident Response Analyst  
**Duration:** January 2025  
**Tools:** Splunk Enterprise, Linux CLI (Bash), Snort/Suricata IDS  
**Frameworks:** MITRE ATT&CK, NIST SP 800-53, NIST SP 800-61

## Executive Summary

Investigated a sustained 37-day network perimeter breach at a financial services organization,
analyzing 2,485 events across firewall, IDS, and VPN authentication logs. Identified a full APT-style
attack chain including credential compromise, lateral movement, persistent C2 beaconing, and
data exfiltration.

## Key Findings

- 🔴 **4 compromised VPN accounts** (alice, bob, jsmith, svc_backup)
- 🔴 **80 C2 beacons** from WORKSTATION-60 to attacker server (198.51.100.77:4444)
- 🔴 **118 brute-force attempts** against svc_backup in 19 minutes
- 🔴 **90 internal scan connections** from VPN-CLIENT-ATTK (10.8.0.23)
- 🔴 **60 exfiltration events** from APP-WEB-01 via HTTP POST uploads
- 🔴 **Firewall misconfiguration:** 72.7% allow rate, port 4444 left open

## Skills Demonstrated

- Splunk SPL query writing (stats, eval, timechart, rex, fieldsummary)
- Linux command-line forensics (grep, awk, sed, cut, sort, uniq)
- Cross-source log correlation (firewall + IDS + VPN)
- MITRE ATT&CK technique mapping
- Detection rule development
- Professional incident documentation

## Full Report

📄 [View Complete 45-Page Incident Response Report](./INCIDENT-REPORT.pdf)
```

**Put this GitHub link on your CV** under the project entry or in your contact info.

---

## 7. LinkedIn Project Section

### How to Add It:

1. Go to your LinkedIn profile → "Add profile section" → "Additional" → "Add projects"
2. **Project Name:** Network Perimeter Breach Investigation — SOC Level 1 Case Study
3. **Associated with:** [Your name / Self-Directed]
4. **Start/End Date:** Jan 2025 – Present
5. **Project URL:** [Your GitHub repository link]
6. **Description:**

```
Conducted a comprehensive incident response investigation of a sustained network perimeter 
breach, analyzing 2,485 events across firewall, IDS, and VPN logs using Linux CLI tools and 
Splunk SIEM.

Key Achievements:
• Mapped a 37-day APT-style attack chain: initial access → lateral movement → C2 beaconing → exfiltration
• Identified 80 C2 beacons, 118 brute-force attempts, and 60 exfiltration events
• Built 5 Splunk detection rules for real-time threat alerting
• Documented findings in a 45-page report with MITRE ATT&CK mapping (14 techniques)
• Skills: Splunk SPL, Linux Forensics, Log Correlation, MITRE ATT&CK, Incident Response

Technologies: Splunk Enterprise, Linux (Bash), Snort/Suricata IDS
```

---

## 8. Interview Talking Points

When interviewers ask about this project, structure your answer using the **STAR method**:

### Situation:
> "I investigated a simulated incident at a financial services firm where the SOC was overwhelmed 
> and potentially missed a perimeter breach. I had access to firewall logs, IDS alerts, and VPN 
> authentication records."

### Task:
> "My goal was to determine if the adversary breached the perimeter, map the full attack chain, 
> identify compromised assets, and recommend remediation."

### Action:
> "I started with CLI reconnaissance — understanding log formats with head/tail, counting events 
> with wc, and using grep/awk/cut/sort/uniq to identify patterns. Then I moved to Splunk for 
> SIEM-scale correlation across all three data sources. I wrote 25+ SPL queries, built cross-source 
> correlation logic, and created 5 detection rules."

### Result:
> "I confirmed a 37-day breach with 4 compromised accounts, 80 C2 beacons, and confirmed data 
> exfiltration. I identified 10 failed security controls and produced a 45-page report with MITRE 
> ATT&CK mapping. The key lesson was the importance of log correlation — the IDS detected 
> everything, but without cross-referencing VPN and firewall data, the SOC missed the big picture."

### Questions to Expect:

| Question | Your Answer Hook |
|----------|---------------|
| "Why Splunk and not another SIEM?" | "Splunk's SPL is industry-standard. Mastering it makes me transferable to any Splunk shop, which most enterprises use." |
| "What was the hardest part?" | "Field extraction in the VPN logs — the username and result fields weren't auto-extracted, so I had to troubleshoot and adapt my queries." |
| "What would you do differently?" | "I'd add NetFlow data to quantify actual exfiltration volume in bytes. The firewall logs showed connections but not data volume." |
| "How does this apply to our SOC?" | "The detection rules I built are directly transferable. The cross-correlation methodology works with any SIEM." |

---

## 9. ATS Optimization Checklist

Before submitting your CV, verify:

- [ ] **"Splunk"** appears at least 3 times
- [ ] **"Incident Response"** appears at least 2 times
- [ ] **"SIEM"** appears at least 2 times
- [ ] **"MITRE ATT&CK"** appears at least once
- [ ] **"Firewall"** and **"IDS"** both appear
- [ ] Numbers are spelled out AND numeric (e.g., "2,485 events" and "two thousand four hundred eighty-five")
- [ ] No fancy formatting that breaks ATS parsing (no tables, no graphics, no headers/footers)
- [ ] PDF is text-selectable (not an image)
- [ ] File name includes your name: `John_Doe_SOC_Analyst_CV.pdf`

---

## 10. Sample One-Page CV Entry (Copy-Paste)

```
TECHNICAL PROJECTS

SOC Level 1 Incident Response — Network Perimeter Breach Investigation
• Analyzed 2,485 security events across firewall, IDS, and VPN logs using Linux CLI and Splunk SIEM
  to investigate a sustained 37-day network intrusion
• Identified full APT-style kill chain: 4 compromised VPN accounts, 80 C2 beacons, 118 credential
  brute-force attempts, and confirmed data exfiltration via HTTP POST uploads
• Built 5 Splunk detection rules (SPL) for real-time alerting on C2, exfiltration, brute force,
  lateral movement, and account compromise
• Mapped 14 MITRE ATT&CK techniques and produced a 45-page incident response report with
  root cause analysis and remediation recommendations
• Tools: Splunk Enterprise, Linux CLI (Bash), Snort/Suricata IDS | Frameworks: MITRE ATT&CK,
  NIST SP 800-53
```

---

## Final Tip: The "So What?" Test

For every bullet point on your CV, ask: **"So what?"**

| Weak | Strong |
|------|--------|
| "Analyzed firewall logs" | "Analyzed 1,284 firewall events and identified a 72.7% allow rate violating NIST default-deny principles" |
| "Used Splunk" | "Wrote 25+ SPL queries correlating 3 data sources to reconstruct a 37-day attack timeline" |
| "Found C2 traffic" | "Detected 80 C2 beacons with clockwork precision, mapped to Meterpreter behavior via sequential ephemeral port analysis" |

Every bullet should answer: **What did you do? How did you do it? What was the outcome?**
