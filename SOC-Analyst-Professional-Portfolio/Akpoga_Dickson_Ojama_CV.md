# AKPOGA DICKSON OJAMA

**SOC Analyst | Cybersecurity Professional**

Almada, Portugal | (+351) 928 211 896 | ojamadickson@gmail.com  
[linkedin.com/in/ojama-d-28a13814a](https://linkedin.com/in/ojama-d-28a13814a) | [github.com/ojamadickson-creator](https://github.com/ojamadickson-creator/SOC-Analyst-Portfolio)

---

SOC Analyst with a solid foundation in threat detection, incident response, and log analysis. I hold the CompTIA Security+, Network+, A+, and CSIS stack, and I spend my time building hands-on skills through home labs, simulated SOC environments, and real-world case studies. I recently completed a full incident response investigation where I analyzed nearly 2,500 security events across firewall, IDS, and VPN logs to map out a 37-day network breach — start to finish. I also run a Security Onion home lab for continuous threat hunting practice. I'm actively preparing for the CompTIA CySA+ to level up my threat analysis game. Based in Almada, Portugal. Bilingual in English and Portuguese. Ready to start immediately.

---

## CERTIFICATIONS

● **CompTIA Security+** | Valid 2023–2029  
● **CompTIA Network+** | Valid 2023–2029  
● **CompTIA A+** | Valid 2023–2029  
● **CompTIA CSIS** | Valid 2023–2029  
● **CompTIA CySA+** | In Preparation  
● **IBM Cybersecurity Fundamentals** | 2022  
● **Junior Pentester Certificate (TryHackMe)** | Completed  
● **QA Manual Testing — Agile & JIRA (Udemy)** | 2022

---

## TECHNICAL SKILLS

**SOC & Threat Detection:** Splunk SPL, SIEM correlation, log analysis, phishing investigation, malware sandboxing (ANY.RUN), VirusTotal, URLScan.io, MITRE ATT&CK mapping, incident triage, IOC documentation

**Network & System Security:** Wireshark, Nmap, IDS/IPS, firewall policy analysis, Active Directory, SCCM, MS Intune/Autopilot, SPF/DKIM/DMARC

**Security Frameworks:** MITRE ATT&CK, NIST SP 800-53, NIST SP 800-61, Unified Kill Chain, Pyramid of Pain, GDPR, ISO 27001

**IT Infrastructure:** Windows, macOS, Linux (Bash), ServiceNow, JIRA, Google Workspace, ticketing platforms

**Programming:** Python (scripting and automation)

---

## PROJECTS

### Network Perimeter Breach Investigation — SOC Level 1 Case Study

*Jan 2025 | Personal Portfolio Project | [github.com/ojamadickson-creator/SOC-Analyst-Portfolio](https://github.com/ojamadickson-creator/SOC-Analyst-Portfolio)*

Investigated a simulated 37-day network intrusion at a financial services firm. I had firewall logs, IDS alerts, and VPN authentication records — and I needed to figure out if the perimeter was breached, how deep the attacker got, and what was stolen. Here's what I found and how I got there:

● Started with the basics — used `head`, `tail`, `wc`, and `grep` to understand log formats and volumes (1,284 firewall events, 983 IDS alerts, 218 VPN records). Then I wrote `awk`, `cut`, `sort`, and `uniq` pipelines to pull out attack patterns: which ports were hit hardest, which external IPs were the noisiest, and what the firewall was actually letting through.

● Found that port 4444 (Metasploit's default) had 127 hits — 87 of them allowed by the firewall. That alone told me something was very wrong. I traced the inbound exploit traffic back to August 26, when an external IP delivered a payload straight to an employee workstation.

● The VPN logs revealed the real story: a service account called `svc_backup` was brute-forced — 118 failed login attempts in 19 minutes with no account lockout. The attacker finally got in at 02:19 on September 3 and was assigned internal IP `10.8.0.23`.

● Two days later, that same IP (`10.8.0.23`) spent 15 hours scanning three internal hosts — the finance server, the web app server, and the compromised workstation — on ports 22, 445, and 3389. The firewall allowed about two-thirds of those connections.

● On September 11, I found the C2 beaconing: the compromised workstation called out to `198.51.100.77:4444` every six hours like clockwork. Eighty beacons over 20 days, each using a new ephemeral port — textbook Meterpreter behavior. The IDS flagged every single one as "ET TROJAN Possible C2 Beaconing" Priority 1. Nobody acted on it.

● By late September, the web app server started uploading large HTTP POSTs to the same attacker IP on ports 80 and 8080. The IDS called it "Potential Data Exfiltration." Sixty upload events. The attacker wasn't just maintaining access — they were stealing data.

● I built five Splunk detection rules using SPL — for C2 beaconing, data exfiltration, VPN brute force, lateral movement scanning, and compromised account detection. Each one uses threshold-based alerting so a real SOC would catch this stuff in real time.

● Mapped the full attack to 14 MITRE ATT&CK techniques across seven tactics. Wrote everything up in a 45-page incident response report with executive summary, timeline, root cause analysis, and remediation steps.

**Tools used:** Splunk Enterprise, Linux CLI (Bash), Snort/Suricata IDS, Python (matplotlib for visualizations)  
**Frameworks:** MITRE ATT&CK, NIST SP 800-53, PCI DSS

---

### SOC Alert Triage Simulation — CEO Phishing Attack

*TryHackMe SOC Simulator, 2026*

● Triaged 36 alerts in a simulated SOC environment, hitting 100% true positive detection and correctly dismissing 71% of false positives. Not bad for a first run.

● Investigated a targeted spear-phishing attack aimed at a CEO. Traced the full chain from the phishing email landing in the inbox, through remote access being established, post-exploitation tools being deployed (PowerView, PowerUp), privilege escalation, all the way to data exfiltration via Robocopy.

● Used the Five Ws methodology and mapped everything to MITRE ATT&CK (T1059.001, T1566.001). Wrote up a formal incident report classified as CRITICAL with full IOC documentation and remediation steps.

---

### Security Onion Home Lab

*Ongoing | Personal Lab*

● Built and maintain a Security Onion home lab for hands-on threat hunting practice. I use it to analyze PCAP files, practice IDS signature tuning, and experiment with SIEM dashboards and detection logic.

---

## PROFESSIONAL EXPERIENCE

### Customer Support Representative | Teleperformance Portugal
*Lisbon, Portugal | April 2025 – May 2026*

● Handled inbound email and chat support for a global tech client, consistently hitting SLA targets and quality benchmarks in a high-volume environment.

● Spotted potential fraud and social engineering attempts during customer interactions — basically applied security awareness principles in real time while doing my day job.

● Worked closely with Product Operations and Engineering to resolve technical issues and escalate anything that looked like a security concern.

● Processed sensitive customer data under strict GDPR protocols — good practice for understanding data protection requirements.

---

### Dedicated Dispatcher & Client Liaison | Postal Box Logistics Inc
*Aurora, CO (Remote) | June 2022 – January 2025*

● Managed communications between clients, carriers, and drivers — keeping everything moving while staying compliant with regulations.

● Built and delivered compliance training for a team of drivers. Cut violations by 20% and boosted team efficiency by 23%. Not security training per se, but it taught me how to make compliance stick with people who don't naturally care about it.

● Maintained a 98% on-time delivery rate through proactive tracking and clear communication.

---

### IT Support & Client Coordinator | 917Smith Inc
*Springfield, OH (Remote) | May 2020 – March 2022*

● Troubleshot hardware, software, and connectivity issues for clients and internal teams.

● Taught colleagues about phishing and social engineering in plain English — no jargon, just practical advice that actually stuck. Reduced security incidents through awareness.

● Resolved 95% of client disputes using structured problem-solving, which directly improved client retention by 25%.

---

### Logistics Manager & Client Relations Lead | Cranston Trucking
*Granham, NC (Remote) | September 2017 – May 2020*

● Managed cross-functional teams and vendor relationships, making sure operations ran smoothly and stayed compliant.

● Streamlined onboarding workflows using digital tools and checklists, cutting onboarding time by 30%.

---

## EDUCATION

**B.Sc. in Cybersecurity** | IU International University of Applied Sciences | Remote | Fifth Semester (Paused)  
Coursework: Network Security, Ethical Hacking, Cryptography, Risk Management, Incident Response, Secure Coding

---

## LANGUAGES

English — Native / Fluent | Portuguese — Conversational (A2)
