# 🔍 SPL Queries — Splunk Enterprise Security

> Collection of SPL queries used for threat detection
> and investigation in Splunk Enterprise Security lab.
> Author: Thumma Lakshmikanth Gari Dinesh
> Role: Junior SOC Analyst
> Tool: Splunk Enterprise Security (ES)

---

## 📋 Query Index

| # | Query Name | Use Case |
|---|-----------|----------|
| 1 | Port Scanning Detection | Reconnaissance |
| 2 | High Firewall Deny Connections | DDoS Detection |
| 3 | VPN Login Activity | Access Monitoring |
| 4 | Failed VPN Logins | Brute Force |
| 5 | Traffic to Well Known Ports | Exploitation |
| 6 | Suspicious Authentication | Credential Attack |
| 7 | Top Blocked Source IPs | Threat Detection |
| 8 | Network Traffic Over Time | SOC Dashboard |

---

## 1️⃣ Port Scanning Detection

```spl
index=* sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
| sort -unique_ports
```
**Use Case:** Detects IPs scanning multiple ports
**Threat:** Reconnaissance / Network Scanning
**MITRE ATT&CK:** T1046 — Network Service Scanning

---

## 2️⃣ High Firewall Deny Connections — DDoS

```spl
index=* sourcetype=firewall action=blocked
| stats count as denied by src_ip
| where denied > 100
| sort -denied
```
**Use Case:** Detects IPs with excessive denied connections
**Threat:** DDoS Attack / Brute Force
**MITRE ATT&CK:** T1498 — Network Denial of Service

---

## 3️⃣ VPN Login Activity

```spl
index=* sourcetype=vpn
| stats count by user, action, src_ip
| sort -count
```
**Use Case:** Monitors all VPN login activity
**Threat:** Unauthorized Access
**MITRE ATT&CK:** T1133 — External Remote Services

---

## 4️⃣ Failed VPN Logins

```spl
index=* sourcetype=vpn action=failed
| stats count by user, src_ip
| sort -count
```
**Use Case:** Detects failed VPN login attempts
**Threat:** Brute Force / Credential Stuffing
**MITRE ATT&CK:** T1110 — Brute Force

---

## 5️⃣ Traffic Towards Well Known Ports

```spl
index=* sourcetype=firewall
| where dest_port IN (22, 23, 80, 443, 3389, 445, 21)
| stats count by dest_port, src_ip
| sort -count
```
**Use Case:** Monitors traffic to sensitive ports
**Threat:** Service Exploitation
**MITRE ATT&CK:** T1021 — Remote Services

---

## 6️⃣ Suspicious Authentication Activity

```spl
index=* sourcetype=firewall OR sourcetype=vpn
| stats count as attempts by user, src_ip
| where attempts > 10
| sort -attempts
```
**Use Case:** Detects suspicious authentication patterns
**Threat:** Credential Attack / Insider Threat
**MITRE ATT&CK:** T1078 — Valid Accounts

---

## 7️⃣ Top Blocked Source IPs

```spl
index=* sourcetype=firewall action=blocked
| stats count by src_ip
| sort -count
| head 10
```
**Use Case:** Identifies most aggressive attacking IPs
**Threat:** Active Attack Campaign
**MITRE ATT&CK:** T1595 — Active Scanning

---

## 8️⃣ Network Traffic Over Time

```spl
index=* sourcetype=firewall
| timechart count by action
```
**Use Case:** Visualizes traffic trends over time
**Threat:** Anomaly Detection
**MITRE ATT&CK:** T1040 — Network Sniffing

---

## 🚨 Incident Review Dashboard

> Splunk Enterprise Security Incident Review showing
> **3191 Notable Events** in last 24 hours

### Active Alerts Detected:
| Alert | Urgency | Domain |
|-------|---------|--------|
| Port Scanning Detection | 🟡 Medium | Network |
| High Firewall DENY — DDoS | 🟡 Medium | Network |
| Suspicious Auth — Arcsight3 | 🟡 Medium | Endpoint |
| Suspicious Auth — ANONYMOUS LOGON | 🟡 Medium | Endpoint |
| VPN Login from 152.57.237.86 | 🟢 Low | Network |

### 📸 Dashboard Screenshot:
[Add your dashboard screenshot here]

---

## 🛠️ Tools Used
- Splunk Enterprise Security (ES)
- SPL (Search Processing Language)
- Splunk Incident Review Dashboard
- Correlation Searches

## 📫 Connect With Me
- LinkedIn: linkedin.com/in/dineshtl
- Email: dineshtl821@gmail.com
- GitHub: github.com/Dineshtl# Splunk-SPL-Queries
SPL queries from SOC internship
