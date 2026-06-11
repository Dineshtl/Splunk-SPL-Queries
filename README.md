# CrowdStrike Falcon EDR — Threat Investigation & Active Response

**Author:** Thumma Lakshmikanth Gari Dinesh  
**Role:** SOC Analyst (Tier 1)  
**Tool:** CrowdStrike Falcon EDR  

---

## Investigation 1 — ChaosRansomwareV4 Ransomware Detection & Containment

### Incident Overview

| Field | Details |
|---|---|
| **Date** | June 7, 2026 |
| **Analyst** | Thumma Lakshmikanth Gari Dinesh |
| **Severity** | 🔴 Critical |
| **Host** | HACKBOOK (Windows 11 Workstation) |
| **Verdict** | True Positive |
| **Status** | Contained |

---

### Step 1 — Alert Detection

While monitoring the CrowdStrike Falcon Activity Dashboard, 
a Critical severity alert was identified in the 
Endpoint Detections queue. The alert showed 75 total 
detections with a Critical priority detection on host 
HACKBOOK detected at 09:25:17 on June 7, 2026.

The triggering filename was **Office 2019.exe.exe** — 
immediately suspicious due to the double .exe.exe extension, 
a classic masquerading technique where malware disguises 
itself as a legitimate application.

**Detection Details:**
- Filename: Office 2019.exe.exe
- Severity: Critical
- Source: On-demand scan
- Tactic: Custom Intelligence via Indicator of Compromise
- Technique ID: CST0005
- IOA Name: IOCPolicySHA256Critical
- Assigned to: Thumma Dinesh

![Detections List](01-detections-list.png)
![Detection Detail](02-detection-detail.png)

---

### Step 2 — Hash Analysis & Threat Intelligence

The SHA256 hash of the file was extracted and analyzed 
using Falcon's built-in threat intelligence:

**SHA256:** 
954d8fcd6b74d76999f9ec033ca855ffdab6595be23039f03bc4c6017fa3932c

**Activity Tab findings:**
- External prevalence: Low — file rarely seen globally
- Internal prevalence: Low — limited spread inside network
- Hosts affected: 2
- Detections: 2
- Last seen: June 7, 2026 10:12:30
- Hash action: Block — Falcon actively blocking this hash

Low external prevalence is a strong malware indicator — 
legitimate software like Microsoft Office has very high 
global prevalence. A rare executable masquerading as 
Office is highly suspicious.

![Hash Activity](03-hash-activity.png)

**Intelligence Tab findings:**

The Intelligence tab delivered the critical finding —
the SHA256 hash was positively matched to the 
**ChaosRansomwareV4** malware family. This is a known 
ransomware strain capable of file encryption, backup 
destruction, and lateral movement across networks.

- Malware Family: ChaosRansomwareV4
- File size: 0 Bytes — hollow/packed file, common evasion
- Last updated: June 7, 2026 11:05:24

**Verdict at this stage: 🔴 TRUE POSITIVE — 
Ransomware confirmed on host HACKBOOK**

![Hash Intelligence](04-hash-intelligence-chaosransomware.png)

---

### Step 3 — Scan Results Review

On-demand scan results were reviewed to understand 
the full scope of the infection:

- Hosts with detections: 1 (HACKBOOK)
- Files scanned: 4
- Files traversed: 98
- **0/2 files quarantined** ⚠️ — malicious files still 
active on host
- Containment status: Normal — host not yet isolated
- Scan initiated by: arvind@siemxpert.com

The fact that 0 files were quarantined confirmed that 
the ransomware was still active and uncontained on 
HACKBOOK — requiring immediate response action.

![Scan Results](05-scan-results.png)

---

### Step 4 — Active Response & Containment

Given the confirmed ransomware identification and active 
threat status, the following response actions were 
immediately executed:

**Action 1 — Network Containment**
Network containment was initiated on host HACKBOOK via 
Falcon's containment feature. This isolates the host 
from all network communication — preventing ransomware 
from spreading laterally to other endpoints or encrypting 
network shares.

- Network containment status: Containment pending ✅
- Host status: Offline ✅
- Host successfully isolated from network

![Network Containment](06-network-containment-pending.png)

**Action 2 — RTR Attempted**
Real Time Response (RTR) session was attempted to connect 
to HACKBOOK for live process investigation and malicious 
process termination. However, RTR was not possible as 
the host was offline following network containment — 
which is expected and correct SOC procedure. 
Containment always takes priority over live forensics 
to prevent further spread.

**Action 3 — Credential Disabling**
As an additional mitigation, HACKBOOK machine credentials 
were disabled to prevent any unauthorized access attempts 
using compromised credentials from the infected host — 
even in the event of partial network access.

---

### Step 5 — Escalation

Following containment and credential disabling, the 
incident was documented and escalated to L2 analyst 
for:
- Full forensic analysis of HACKBOOK
- Recovery and restoration procedures
- Investigation of the second affected host
- Root cause analysis of initial infection vector

---

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Evidence |
|---|---|---|---|
| Defense Evasion | T1036 | Masquerading | Double .exe.exe extension |
| Impact | T1486 | Data Encrypted for Impact | ChaosRansomwareV4 family |
| Initial Access | T1566 | Phishing | Likely delivery method |

---

### Conclusion

A Critical ransomware alert was detected on host HACKBOOK 
via CrowdStrike Falcon EDR on June 7, 2026. The file 
Office 2019.exe.exe was confirmed as ChaosRansomwareV4 
through SHA256 hash intelligence matching. Immediate 
response actions were taken including network containment 
and credential disabling to prevent lateral movement and 
further compromise. The incident was escalated to L2 for 
full forensic investigation and recovery.

**Final Verdict: 🔴 TRUE POSITIVE — ChaosRansomwareV4 
Ransomware | Contained & Escalated**

---

## Skills Demonstrated

- Endpoint alert triage — Critical severity
- SHA256 hash analysis and threat intelligence
- IOC identification and validation  
- Malware family identification — ChaosRansomwareV4
- On-demand scan result interpretation
- Network containment execution
- Credential disabling as mitigation
- MITRE ATT&CK mapping
- Incident escalation procedure

---

## Connect

- LinkedIn: linkedin.com/in/dineshtl
- GitHub: github.com/Dineshtl
- Email: dineshtl821@gmail.com
