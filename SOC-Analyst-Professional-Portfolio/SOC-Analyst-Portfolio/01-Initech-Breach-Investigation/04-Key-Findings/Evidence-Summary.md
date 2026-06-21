# Evidence Summary

Consolidated evidence from all three log sources (firewall, IDS, VPN) supporting the breach determination.

---

## Timeline of Key Events

| Date | Time | Event | Source |
|------|------|-------|--------|
| August 25 | 08:25:10 | First successful VPN login (compromised credentials) | VPN logs |
| August 25 | Various | Initial reconnaissance and exploitation attempts | Firewall, IDS |
| September 3 | 02:00-02:19 | Brute force attack on svc_backup (118 attempts) | VPN logs |
| September 3 | 02:19:40 | Successful svc_backup login, assigned IP 10.8.0.23 | VPN logs |
| September 5 | Multi-hour | Lateral movement scan from 10.8.0.23 | Firewall, IDS |
| September 11 | Ongoing | C2 beaconing begins (80 beacons over 20 days) | Firewall, IDS |
| September 27 | Ongoing | Data exfiltration via HTTP POST (60 events) | Firewall, IDS |
| September 30 | 19:00:00 | Final C2 beacon before logs end | Firewall, IDS |

## Compromised Accounts

| Username | Compromise Method | Attacker IP | VPN IP |
|----------|------------------|-------------|--------|
| alice | Stolen credentials | 203.0.113.45 | Unknown |
| bob | Stolen credentials | 203.0.113.45 | Unknown |
| jsmith | Stolen credentials | 203.0.113.45 | Unknown |
| svc_backup | Brute force (118 attempts) | 203.0.113.45 | 10.8.0.23 |

## Critical Indicators

- **Attacker IP:** 203.0.113.45
- **C2 Server:** 198.51.100.77:4444
- **Exfiltration Ports:** 80, 8080
- **Primary Victim Host:** WORKSTATION-60 (10.0.0.60)
- **Lateral Movement Source:** 10.8.0.23
