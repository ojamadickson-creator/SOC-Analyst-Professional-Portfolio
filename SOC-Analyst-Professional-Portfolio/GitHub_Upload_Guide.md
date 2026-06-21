# How to Upload the Initech Project to GitHub Professionally

A clean, well-organized GitHub repository can be the difference between a recruiter skimming past and clicking through every folder. Here is how to structure and present the Initech Breach Investigation so it looks like the work of a seasoned analyst.

---

## Step 1: Create the Folder Structure on Your Computer

Create the folders below on your local machine before uploading anything. Every file must have a home.

```
SOC-Analyst-Portfolio/
├── 01-Initech-Breach-Investigation/
│   ├── 01-Executive-Summary/
│   │   └── README.md
│   ├── 02-CLI-Investigation/
│   │   ├── Phase-01-Initial-Log-Exploration.md
│   │   ├── Phase-02-Firewall-Log-Analysis.md
│   │   ├── Phase-03-IDS-Alert-Analysis.md
│   │   ├── Phase-04-VPN-Authentication-Analysis.md
│   │   ├── Phase-05-Cross-Correlation-and-Timeline.md
│   │   └── Screenshots/
│   ├── 03-Splunk-Investigation/
│   │   ├── Phase-06-Data-Validation.md
│   │   ├── Phase-07-IDS-Investigation-Splunk.md
│   │   ├── Phase-08-Firewall-Investigation-Splunk.md
│   │   ├── Phase-09-VPN-Investigation-Splunk.md
│   │   ├── Phase-10-Cross-Source-Correlation.md
│   │   └── Screenshots/
│   ├── 04-Key-Findings/
│   │   ├── MITRE-ATT&CK-Mapping.md
│   │   ├── Root-Cause-Analysis.md
│   │   └── Evidence-Summary.md
│   ├── 05-Detection-Rules/
│   │   ├── Splunk-Detection-Rules.md
│   │   └── SPL-Query-Reference.md
│   ├── 06-Reports/
│   │   └── Initech-Incident-Response-Report.pdf
│   └── README.md
├── 02-SOC-Alert-Triage-Simulation/
│   ├── README.md
│   └── Screenshots/
├── Assets/
│   ├── Charts/
│   │   ├── attack-phases-chart.png
│   │   ├── c2-beaconing-timeline.png
│   │   ├── vpn-brute-force-chart.png
│   │   └── kill-chain-diagram.png
│   └── Logos/
│       └── (optional: your personal logo or badge)
└── README.md
```

### Naming Rules

- **Folders:** Use Title-Case with hyphens (e.g., `02-CLI-Investigation`).
- **Files:** Use descriptive names with hyphens (e.g., `Phase-02-Firewall-Log-Analysis.md`).
- **Screenshots:** Prefix with the phase number (e.g., `P02-firewall-allow-vs-block.png`).
- **Never use spaces** in file or folder names — they break URLs and make command-line navigation painful.

---

## Step 2: Write the Main README.md

The `README.md` at the root of your repository is your storefront. Recruiters will decide whether to dig deeper within 10 seconds. Copy the template below into `/README.md` and fill in your details.

```markdown
# SOC Analyst Portfolio

A collection of hands-on cybersecurity investigations, incident response case studies, and threat detection projects. Each project documents real-world SOC workflows using industry-standard tools and frameworks.

---

## Featured Project: Network Perimeter Breach Investigation

**Type:** SOC Level 1 Incident Response Investigation  
**Platform:** TryHackMe — Network Security Essentials  
**Date:** 2026  
**Status:** Completed

### Overview

A full forensic investigation of a sustained network perimeter breach at Initech Corp, a simulated financial services firm. The attacker maintained unauthorized access for 37 days, establishing persistent command-and-control over an employee workstation and exfiltrating data from the internal web application server.

The investigation employed both **command-line forensics** (Linux CLI) and **Splunk SIEM analysis** to correlate 2,485 events across three independent log sources: firewall logs, IDS alerts, and VPN authentication records.

### What I Did

- Analyzed 2,485 security events using Linux CLI pipelines (grep, awk, cut, sort, uniq) and Splunk SPL queries
- Identified port 4444 (Metasploit default) as the primary attack vector with 87 of 127 connections allowed by the firewall
- Discovered a 118-attempt brute force against the `svc_backup` VPN account with no account lockout policy
- Mapped lateral movement across three critical internal hosts (finance server, web app server, workstation)
- Detected 80 C2 beacons every 6 hours for 20 days — textbook Meterpreter behavior
- Uncovered 60 HTTP POST upload events indicating confirmed data exfiltration
- Built 5 production-ready Splunk detection rules with threshold-based alerting
- Mapped 14 MITRE ATT&CK techniques across 7 tactics
- Authored a 45-page incident response report with executive summary, timeline, root cause analysis, and remediation steps

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
├── 01-Executive-Summary/
├── 02-CLI-Investigation/           # Command-line forensics (Phases 1–5)
├── 03-Splunk-Investigation/        # SIEM analysis (Phases 6–10)
├── 04-Key-Findings/                # MITRE mapping, root cause, evidence
├── 05-Detection-Rules/             # Splunk SPL detection rules
└── 06-Reports/                     # Full PDF incident response report
```

### Key Findings at a Glance

| Finding | Detail |
|---------|--------|
| Perimeter Breach | Day 1 (August 25) via compromised VPN credentials |
| Brute Force | 118 attempts on `svc_backup` in 19 minutes — no lockout |
| Lateral Movement | 15-hour scan of 3 hosts on ports 22, 445, 3389 |
| C2 Beaconing | 80 beacons every 6 hours for 20 days |
| Data Exfiltration | 60 HTTP POST uploads on ports 80/8080 |
| Firewall Misconfig | 72.7% allow rate, port 4444 open |
| MITRE Techniques | 14 techniques across 7 tactics |

[View Full Investigation Details](01-Initech-Breach-Investigation/README.md)

---

## Project 2: SOC Alert Triage Simulation

**Type:** SOC Alert Triage & Incident Investigation  
**Platform:** TryHackMe — SOC Simulator  
**Date:** 2026  
**Status:** Completed

Triaged 36 alerts in a simulated SOC environment, achieving 100% true positive detection. Investigated a targeted CEO spear-phishing attack, tracing the full kill chain from initial email delivery through PowerView/PowerUp exploitation to data exfiltration via Robocopy.

[View Details](02-SOC-Alert-Triage-Simulation/README.md)

---

## About Me

SOC Analyst with a solid foundation in threat detection, incident response, and log analysis. CompTIA Security+, Network+, A+, and CSIS certified. Based in Almada, Portugal.

- LinkedIn: [linkedin.com/in/ojama-d-28a13814a](https://linkedin.com/in/ojama-d-28a13814a)
- Email: ojamadickson@gmail.com
```

---

## Step 3: Write the Project-Specific README.md

Create `/01-Initech-Breach-Investigation/README.md` with a detailed project index. This acts as a table of contents for anyone exploring the investigation.

```markdown
# Network Perimeter Breach Investigation

**Organization:** Initech Corp (Simulated Financial Services Firm)  
**Investigation Period:** 37 days (August – September 2025)  
**Total Events Analyzed:** 2,485  
**Final Verdict:** Perimeter Breached — Confirmed

---

## Investigation Phases

### Part A: Command-Line Investigation

| Phase | Title | Description |
|-------|-------|-------------|
| [Phase 1](02-CLI-Investigation/Phase-01-Initial-Log-Exploration.md) | Initial Log Exploration | Log format reconnaissance, volume assessment, tail analysis |
| [Phase 2](02-CLI-Investigation/Phase-02-Firewall-Log-Analysis.md) | Firewall Log Analysis | Port frequency, ALLOW vs BLOCK ratios, blocked IP analysis |
| [Phase 3](02-CLI-Investigation/Phase-03-IDS-Alert-Analysis.md) | IDS Alert Analysis | C2 beaconing, Metasploit detection, per-asset alert patterns |
| [Phase 4](02-CLI-Investigation/Phase-04-VPN-Authentication-Analysis.md) | VPN Auth Analysis | Brute force detection, compromised account identification |
| [Phase 5](02-CLI-Investigation/Phase-05-Cross-Correlation-and-Timeline.md) | Cross-Correlation | Full attack timeline, kill chain reconstruction |

### Part B: Splunk SIEM Investigation

| Phase | Title | Description |
|-------|-------|-------------|
| [Phase 6](03-Splunk-Investigation/Phase-06-Data-Validation.md) | Data Validation & Field Discovery | Sourcetype verification, field mapping |
| [Phase 7](03-Splunk-Investigation/Phase-07-IDS-Investigation-Splunk.md) | IDS Investigation in Splunk | C2 beaconing queries, alert correlation |
| [Phase 8](03-Splunk-Investigation/Phase-08-Firewall-Investigation-Splunk.md) | Firewall Investigation in Splunk | Allowed/blocked traffic analysis |
| [Phase 9](03-Splunk-Investigation/Phase-09-VPN-Investigation-Splunk.md) | VPN Investigation in Splunk | Brute force and compromised account queries |
| [Phase 10](03-Splunk-Investigation/Phase-10-Cross-Source-Correlation.md) | Cross-Source Correlation | Multi-source SPL correlation across all log types |

---

## Key Artifacts

- [MITRE ATT&CK Mapping](04-Key-Findings/MITRE-ATT&CK-Mapping.md)
- [Root Cause Analysis](04-Key-Findings/Root-Cause-Analysis.md)
- [Evidence Summary](04-Key-Findings/Evidence-Summary.md)
- [Splunk Detection Rules](05-Detection-Rules/Splunk-Detection-Rules.md)
- [Full Incident Response Report (PDF)](06-Reports/Initech-Incident-Response-Report.pdf)

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
```

---

## Step 4: Populate the Phase Markdown Files

Each phase file should follow this consistent template:

```markdown
# Phase X — [Phase Title]

## Objective

One sentence describing what this phase aimed to achieve.

## Commands Used

### Command 1: [Brief Description]

```bash
[exact command here]
```

**Why this command:** 2–3 sentences explaining the logic behind the command and what it reveals.

**Expected Output:**
```
[paste or describe the output]
```

### Command 2: [Brief Description]

```bash
[exact command here]
```

**Why this command:** ...

---

## Key Findings

- Bullet point summarizing the most important discovery from this phase
- Another key insight
- Any anomaly or red flag

## Screenshot Evidence

![Description of screenshot](Screenshots/P0X-descriptive-filename.png)

---

## Insights & Conclusions

A short paragraph tying the findings from this phase into the broader investigation narrative.
```

### Screenshot Naming Convention

Place all screenshots in the `Screenshots/` folder within each phase directory. Name them like this:

```
P02-firewall-allow-vs-block-ratio.png
P02-top-blocked-ips.png
P03-c2-beaconing-alerts.png
P03-per-asset-alert-count.png
P04-svc_backup-brute-force.png
P04-compromised-accounts-table.png
P05-attack-timeline-chart.png
P07-splunk-c2-beaconing-query.png
P10-cross-source-correlation-results.png
```

---

## Step 5: Upload Everything to GitHub

### If You Are New to Git

1. **Install Git** (if you haven't already):
   - Windows: [git-scm.com](https://git-scm.com)
   - macOS: `brew install git`
   - Linux: `sudo apt install git`

2. **Open a terminal** and navigate to the project folder:

```bash
cd /path/to/SOC-Analyst-Portfolio
```

3. **Initialize a Git repository:**

```bash
git init
```

4. **Stage all files:**

```bash
git add .
```

5. **Commit with a descriptive message:**

```bash
git commit -m "Initial commit: Initech breach investigation with CLI and Splunk analysis"
```

6. **Create a new repository on GitHub:**
   - Go to [github.com/new](https://github.com/new)
   - Name it `SOC-Analyst-Portfolio`
   - Set it to **Public** (recruiters need to see it)
   - Do **not** initialize with a README — you already have one
   - Click **Create repository**

7. **Connect your local repo to GitHub:**

```bash
git remote add origin https://github.com/ojamadickson-creator/SOC-Analyst-Portfolio.git
```

8. **Push everything to GitHub:**

```bash
git branch -M main
git push -u origin main
```

9. **Done.** Your portfolio is live at:
   `https://github.com/ojamadickson-creator/SOC-Analyst-Portfolio`

---

## Step 6: Keep It Updated (Ongoing)

Every time you add new projects or make improvements:

```bash
git add .
git commit -m "Description of what changed"
git push origin main
```

Commit message examples:

```
"Add Phase 7 Splunk IDS investigation with screenshots"
"Update MITRE ATT&CK mapping with 3 new techniques"
"Fix typo in firewall analysis — corrected port count"
"Add executive summary to incident response report"
```

---

## Pro Tips for a Professional GitHub Presence

| Do | Don't |
|----|-------|
| Write descriptive commit messages | Use vague messages like "update" or "fix" |
| Keep the README updated with your latest work | Let it go stale with outdated info |
| Use proper Markdown formatting (headers, tables, code blocks) | Dump unformatted text walls |
| Add a concise project description in the GitHub "About" section | Leave the About section empty |
| Pin this repository to your GitHub profile | Let it get buried under other repos |
| Add topic tags: `cybersecurity`, `soc-analyst`, `incident-response`, `splunk`, `threat-detection` | Skip tagging entirely |
| Include a LICENSE file (MIT is fine for portfolio work) | Leave it looking unfinished |
| Add a profile README at `github.com/ojamadickson-creator/ojamadickson-creator` | Have an empty GitHub profile |

---

## Optional: Add a GitHub Profile README

Create a special repository named exactly `ojamadickson-creator` and add a `README.md`. This displays on your GitHub profile page like a personal landing card.

```markdown
### Hi, I'm Dickson — SOC Analyst

🔐 **CompTIA Security+ | Network+ | A+ | CSIS**  
🎯 Building hands-on SOC skills through incident response and threat hunting  
🌍 Based in Almada, Portugal | Bilingual: English & Portuguese  
📚 Preparing for **CySA+**

### Featured Work

🚨 **[Network Perimeter Breach Investigation](link-to-repo)** — Full IR case study analyzing 2,485 events across firewall, IDS, and VPN logs  
🎣 **[SOC Alert Triage Simulation](link)** — 36-alert triage exercise with 100% true positive detection  

### Tools I Work With

Splunk | Wireshark | Snort/Suricata | Nmap | Python | Linux CLI | MITRE ATT&CK

📫 **ojamadickson@gmail.com**  
💼 **[LinkedIn](https://linkedin.com/in/ojama-d-28a13814a)**
```
