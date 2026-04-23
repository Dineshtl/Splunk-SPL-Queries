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
### ⚠️ Investigation Finding — VPN/User Activity:
- **Suspicious User:** jan2025
- **Source IP:** 10.212.134.201
- **Allowed:** 247 connections
- **Blocked:** 210 connections
- **Verdict: ⚠️ SUSPICIOUS — High blocked to allowed ratio needs investigation**
- **Action: Investigate jan2025 user activity + Check if IP is authorized**

---

## 4️⃣ Failed VPN Logins

```spl
index=main sourcetype=fortigate_traffic action=failure
| stats count by user, src_ip
| sort -count
```
**Use Case:** Detects failed VPN login attempts
**Threat:** Brute Force / Credential Stuffing
**MITRE ATT&CK:** T1110 — Brute Force
<img width="1916" height="915" alt="Screenshot 2026-04-23 114713" src="https://github.com/user-attachments/assets/a21ef279-c5e0-409d-b79c-0039d85786a9" />

### 🚨 Investigation Finding — Suspicious Auth/Botnet:
- **Attack Type:** Coordinated Botnet Attack
- **Target Account:** admin
- **Attacking Subnet:** 85.11.187.x (multiple IPs)
- **Attempts per IP:** ~990 each
- **Total Events:** 98,538
- **Pattern:** Same subnet, same target, 
  same attempt count = Automated botnet
- **Verdict: 🔴 TRUE POSITIVE — CRITICAL
  Botnet Credential Stuffing Attack on admin account**
- **Action: Block entire 85.11.187.0/24 subnet + 
  Lock admin account + Escalate to L2 immediately**
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
<img width="1911" height="907" alt="image" src="https://github.com/user-attachments/assets/4d9dbddd-295c-454d-9de5-6428c617c075" />
### 🚨 Investigation Finding — Well Known Ports:
- **Most Targeted Port:** 443 (HTTPS)
- **Critical Internal IP:** 192.168.0.3 — 31,085 hits
- **Botnet IPs Reappearing:** 85.11.187.x subnet
- **Total Events:** 47,306
- **Verdict: 🔴 TRUE POSITIVE**
  - Internal machine 192.168.0.3 possibly compromised
  - Botnet targeting HTTPS services
- **Action: Isolate 192.168.0.3 + Block 
  85.11.187.0/24 subnet + Investigate HTTPS service**
---

## 6️⃣ Suspicious Authentication Activity

```spl
index=main sourcetype=fortigate_traffic protocol_version=ipv4
| stats count as attempts by src_ip
| where attempts > 10
| sort -attempts
```
**Use Case:** Detects suspicious authentication patterns
**Threat:** Credential Attack / Insider Threat
**MITRE ATT&CK:** T1078 — Valid Accounts
<img width="1912" height="864" alt="Screenshot 2026-04-23 115501" src="https://github.com/user-attachments/assets/31a1362a-2816-4193-9cc9-a25ae2330633" />

### 🚨 Investigation Finding — Suspicious Auth:
- **Most Suspicious:** 192.168.0.24 — 101,431 attempts
- **Second:** 192.168.0.3 — 28,752 attempts
- **Persistent Attacker:** 79.124.62.122 (seen in all queries!)
- **Total Events:** 143,673
- **Verdict: 🔴 TRUE POSITIVE — CRITICAL**
  - Multiple internal machines compromised
  - Persistent external attacker identified
  - Possible lateral movement in progress
- **Action: 
  - Isolate 192.168.0.24 immediately
  - Block 79.124.62.122 on all firewalls
  - Initiate full incident response
  - Escalate to L2/L3 immediately**
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
<img width="1891" height="875" alt="image" src="https://github.com/user-attachments/assets/9409fafa-d7d0-4d46-9cb8-e94ba0f895c4" />
### 🔴 Investigation Finding — Top Blocked IPs:
- **Most Blocked:** 77.90.185.43 — 11,841 times
- **Persistent Attacker:** 79.124.62.122 — 4,268 (appeared in 4 queries!)
- **Compromised Internal IPs:**
  - 192.168.0.125 — 2,768 blocks
  - 192.168.0.24 — 1,712 blocks
  - 192.168.0.127 — 989 blocks
- **Total Events:** 41,267
- **Verdict: 🔴 TRUE POSITIVE**
- **Action: Block 77.90.185.43 + 79.124.62.122 permanently + Isolate internal machines**
---

## 8️⃣ Network Traffic Over Time

```spl
index=main sourcetype=fortigate_traffic
| timechart span=1h count by action
```
**Use Case:** Visualizes traffic trends over time
**Threat:** Anomaly Detection
**MITRE ATT&CK:** T1040 — Network Sniffing
<img width="1914" height="913" alt="Screenshot 2026-04-23 120714" src="https://github.com/user-attachments/assets/15bc2e8f-8881-46b8-9c1a-08aa98d55c22" />

### 📊 Network Traffic Analysis — 24 Hours:
- **Total Events:** 2,390,839
- **Allowed Traffic:** ~100,000/hour (normal baseline)
- **Blocked Traffic:** ~1,900/hour (consistent attack)
- **Peak Attack Time:** 16:00-17:00 (highest blocked)
- **Verdict: Network under continuous attack 
  but firewall blocking effectively**
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
