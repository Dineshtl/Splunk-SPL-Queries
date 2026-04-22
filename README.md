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
index=main sourcetype=fortigate_traffic
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
| sort -unique_ports
```
**Use Case:** Detects IPs scanning multiple ports
**Threat:** Reconnaissance / Network Scanning
**MITRE ATT&CK:** T1046 — Network Service Scanning
<img width="1909" height="908" alt="Screenshot 2026-04-22 170511" src="https://github.com/user-attachments/assets/841418d5-03fa-4ed7-8018-95295fdfbe00" />

### 🚨 Investigation Finding — Port Scanning:
- **Most Aggressive IP:** 79.124.62.122 — 1137 ports
- **Total Events:** 692,068
- **Internal Scanner:** 192.168.0.3 — 57 ports
- **Suspicious:** 8.8.8.8 (Google DNS) — 52 ports
- **Verdict: 🔴 TRUE POSITIVE — Active Port Scanning**
- **Action: Block external IPs + Investigate 
  internal IP 192.168.0.3 immediately**

---

## 2️⃣ High Firewall Deny Connections — DDoS

```spl
index=main sourcetype=fortigate_traffic action=blocked
| stats count as denied by src_ip
| where denied > 100
| sort -denied
```
**Use Case:** Detects IPs with excessive denied connections
**Threat:** DDoS Attack / Brute Force
**MITRE ATT&CK:** T1498 — Network Denial of Service
<img width="1911" height="913" alt="image" src="https://github.com/user-attachments/assets/3daba6b2-6341-4b36-835e-6eaff6cfe8a7" />

### 🚨 Investigation Finding — DDoS/Firewall Deny:
- **Top Attacker:** 79.124.62.122 — 4,426 denials
- **Second Attacker:** 165.154.102.253 — 3,600 denials
- **Suspicious Internal IPs:**
  - 192.168.0.125 — 2,825 denials
  - 192.168.0.24 — 1,980 denials
  - 192.168.0.127 — 1,003 denials
- **Total Events:** 33,396
- **Verdict: 🔴 TRUE POSITIVE — Active DDoS Attack
  + Possible compromised internal machines**
- **Action: Block external IPs + Isolate internal 
  machines for investigation**
---

## 3️⃣ VPN Login Activity

```spl
index=main sourcetype=fortigate_traffic
| stats count by user, action, src_ip
| sort -count
```
**Use Case:** Monitors all VPN login activity
**Threat:** Unauthorized Access
**MITRE ATT&CK:** T1133 — External Remote Services
<img width="1909" height="785" alt="image" src="https://github.com/user-attachments/assets/9ec7286a-3547-4831-b67c-74082298cbee" />


---

## 4️⃣ Failed VPN Logins

```spl
index=main sourcetype=fortigate_traffic action=failed
| stats count by user, src_ip
| sort -count
```
**Use Case:** Detects failed VPN login attempts
**Threat:** Brute Force / Credential Stuffing
**MITRE ATT&CK:** T1110 — Brute Force

---

## 5️⃣ Traffic Towards Well Known Ports

```spl
index=main sourcetype=fortigate_traffic
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
index=main sourcetype=fortigate_traffic
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
index=main sourcetype=fortigate_traffic action=blocked
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
index=main sourcetype=fortigate_traffic
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
