# SOC Alert Triage Simulation - CEO Phishing Attack

**Type:** SOC Alert Triage & Incident Investigation  
**Platform:** TryHackMe - SOC Simulator  
**Date:** TryHackMe, 2026  
**Status:** Completed

---

## Overview

This project documents a simulated SOC alert triage exercise involving a targeted spear-phishing attack against a CEO. The investigation required analyzing 36 alerts, distinguishing true positives from false positives, and tracing the full kill chain from initial email delivery to data exfiltration.

## Results

- **Total Alerts Triaged:** 36
- **True Positive Detection Rate:** 100%
- **False Positive Dismissal Rate:** 71%

## Investigation Summary

The attack began with a spear-phishing email delivered to the CEO's inbox. Once the initial payload was executed, the attacker established remote access, deployed post-exploitation tools (PowerView and PowerUp), escalated privileges, and exfiltrated sensitive data using Robocopy.

### Kill Chain Traced

1. **Initial Access:** Spear-phishing email (T1566.001)
2. **Execution:** PowerShell-based payload delivery (T1059.001)
3. **Persistence:** Remote access tool installation
4. **Privilege Escalation:** PowerUp exploitation
5. **Discovery:** PowerView reconnaissance
6. **Collection:** Sensitive data identified and staged
7. **Exfiltration:** Data transferred via Robocopy

### Methodology Applied

- **Five Ws Framework:** Who, What, When, Where, Why applied to each alert
- **MITRE ATT&CK Mapping:** T1059.001 (PowerShell), T1566.001 (Spear-phishing Attachment)
- **Severity Classification:** CRITICAL
- **IOC Documentation:** Full indicators of compromise documented
- **Remediation Steps:** Containment and recovery actions recommended

## Tools Used

- TryHackMe SOC Simulator
- Log analysis techniques
- MITRE ATT&CK Framework
- Incident reporting methodology

## Screenshots

Investigation screenshots are available in the [Screenshots/](Screenshots/) folder.

---

*This project demonstrates practical SOC analyst skills in alert triage, incident investigation, and threat analysis in a simulated enterprise environment.*
