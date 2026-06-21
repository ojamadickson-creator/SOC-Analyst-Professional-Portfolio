# Splunk Detection Rules

Production-ready SPL detection rules based on findings from the Initech breach investigation. Each rule uses threshold-based alerting to catch similar attacks in real time.

---

## Rule 1: C2 Beaconing Detection

**Description:** Detects repeated outbound connections to the same external IP and port at regular intervals - indicative of command-and-control beaconing.

**Severity:** Critical

**SPL Query:**
```spl
index=network_logs sourcetype=firewall_logs
| stats count by src_ip, dst_ip, dst_port
| where count > 5
| eval alert=if(count > 10, "CRITICAL: Possible C2 Beaconing", "WARNING: Suspicious repeated connections")
| table src_ip, dst_ip, dst_port, count, alert
```

**Trigger Condition:** More than 5 connections from the same internal IP to the same external IP:port combination.

---

## Rule 2: Data Exfiltration Detection

**Description:** Detects large HTTP POST uploads to external IPs, indicating potential data exfiltration.

**Severity:** High

**SPL Query:**
```spl
index=network_logs sourcetype=ids_logs
| search alert="*Potential Data Exfiltration*"
| stats count by src_ip, dst_ip, dst_port
| where count > 3
| table src_ip, dst_ip, dst_port, count
```

**Trigger Condition:** 3 or more "Potential Data Exfiltration" alerts from the same source IP.

---

## Rule 3: VPN Brute Force Detection

**Description:** Detects multiple failed VPN login attempts followed by a successful login - indicative of brute force attacks.

**Severity:** Critical

**SPL Query:**
```spl
index=network_logs sourcetype=vpn_logs
| stats count(eval(result="FAIL")) as failed, count(eval(result="SUCCESS")) as success by username, src_ip
| where failed > 10 AND success > 0
| eval risk_score=failed*10
| table username, src_ip, failed, success, risk_score
```

**Trigger Condition:** More than 10 failed logins with at least 1 success from the same source IP.

---

## Rule 4: Lateral Movement Detection

**Description:** Detects internal scanning behavior from VPN-assigned IPs targeting multiple internal hosts.

**Severity:** High

**SPL Query:**
```spl
index=network_logs sourcetype=firewall_logs action=ALLOW
| eval src_subnet=if(match(src_ip, "^10\.[0-9]+\.[0-9]+\.[0-9]+$"), "internal", "external")
| eval dst_subnet=if(match(dst_ip, "^10\.[0-9]+\.[0-9]+\.[0-9]+$"), "internal", "external")
| where src_subnet="internal" AND dst_subnet="internal"
| stats dc(dst_ip) as unique_targets, dc(dst_port) as unique_ports, count as total_connections by src_ip
| where unique_targets > 2 AND unique_ports > 2
| table src_ip, unique_targets, unique_ports, total_connections
```

**Trigger Condition:** Internal IP connecting to more than 2 unique internal targets on more than 2 unique ports.

---

## Rule 5: Compromised Account Detection

**Description:** Detects successful VPN logins from known malicious IPs or IPs with high failure rates.

**Severity:** Critical

**SPL Query:**
```spl
index=network_logs sourcetype=vpn_logs result=SUCCESS
| lookup malicious_ips src_ip OUTPUT is_malicious
| where is_malicious="true"
| stats count by username, src_ip, assigned_ip
| table username, src_ip, assigned_ip, count
```

**Trigger Condition:** Any successful VPN login from an IP flagged as malicious.

---

## Implementation Notes

- All rules should be scheduled to run every 15 minutes for near real-time detection.
- Adjust thresholds based on your organization's baseline traffic patterns.
- Correlate alerts across multiple rules for higher-confidence detections.
- Integrate with SOAR platform for automated response actions.
