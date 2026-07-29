# 📋 Log Analysis Notes
### How the Logs Were Investigated | auth.log + syslog.log

---

## Step 1 — Establishing the Baseline

Before looking for threats, I read through all **09 March** entries from both log files
to understand what normal activity looks like on webserver01.

**Normal patterns identified:**
- `certbot renew` cron jobs running at irregular intervals (legitimate SSL renewal)
- `logrotate` cron jobs (legitimate log management)
- SSH logins by `aritra`, `ubuntu`, `deploy` — all via **publickey** authentication
- systemd sessions started for `deploy` user (deployment activity)
- DHCP lease renewals for `eth0` → `10.0.0.15`
- nginx reload events tied to certbot renewal

This baseline made the 10 March anomalies immediately obvious.

---

## Step 2 — Identifying the First Anomaly

Scanning 10 March entries, the very first line that broke the baseline pattern:

```
Mar 10 03:14:02 webserver01 sshd[...]: Invalid user "database" from 198.51.100.23
```

**Why this stood out:**
- Time: 03:14 AM — no legitimate admin activity occurs at this hour
- User: "database" — not a valid system account
- IP: 198.51.100.23 — never appeared in 09 March baseline logs

---

## Step 3 — Cross-Correlating Both Log Files

This was the most important step. Neither log told the complete story alone.

**auth.log alone showed:**
- SSH brute-force attempts
- Successful login at 03:45:16
- sudo escalation commands
- New user creation

**syslog.log alone showed:**
- Cron job executing `curl | bash` at 03:20
- IPTABLES outbound connections to 192.0.2.99
- tar archive creation (EXECVE)
- Large outbound data packets

**Combined, the two logs revealed:**

The C2 cron was already **executing at 03:20** while the brute-force was still ongoing
in auth.log at 03:14–03:43. This created a critical timeline question:

> How was the cron job installed before the SSH login succeeded at 03:45?

**Possible explanations:**
1. A prior compromise vector exists that wasn't captured in these logs
2. The cron was installed during a previous undetected session
3. The log timestamps between auth.log and syslog.log may have minor discrepancies

This is documented as a gap requiring further investigation — specifically reviewing
nginx access logs and web application logs for a possible prior web shell.

---

## Step 4 — Building the Full Timeline

Once both logs were read completely, I built the timeline by:

1. Merging all 10 March events sorted by timestamp
2. Grouping events into attack phases
3. Assigning each event to an incident (INC-001 through INC-009)
4. Identifying gaps where evidence was likely destroyed (bash_history wipe)

---

## Step 5 — Identifying Normal vs. Suspicious Events

### Normal (Safe) Events on 10 March:
```
07:05  systemd: Reloaded nginx                      ← legitimate, matches baseline
07:26  certbot renew cron                           ← scheduled, matches baseline
08:22  Session started for user deploy              ← known legitimate user
09:09  Session started for user deploy              ← known legitimate user
09:21  DHCP lease renewal — eth0 → 10.0.0.15       ← matches baseline
17:07+ Sessions for aritra, ubuntu, deploy          ← all legitimate, public-key auth
```

### Suspicious Events on 10 March:
```
03:14  Invalid user attempts from 198.51.100.23     ← NEW IP, off-hours, invalid users
03:20  curl | bash cron executing                   ← never in baseline
03:20  IPTABLES-OUT to 192.0.2.99                  ← new external IP, off-hours
03:45  Accepted password for backup                 ← password auth (baseline = publickey)
03:46  sudo /bin/bash (root shell)                  ← escalation, 3 AM
03:47  useradd sysupdate                            ← no change window, 3 AM
03:48  NOPASSWD >> /etc/sudoers                     ← never in baseline
03:23  tar czf /tmp/.cache_bkp.tar.gz              ← hidden filename, sensitive paths
03:23+ IPTABLES-OUT PSH+ACK+FIN to 192.0.2.99     ← data leaving the network
03:48  echo > .bash_history                         ← anti-forensics
06:03  Accepted password for sysupdate              ← non-existent user in baseline
12:10  Failed password for root from 198.51.100.23  ← same attacker IP, later in day
```

---

## Tools Used for Log Analysis

| Tool / Method | Purpose |
|---|---|
| Manual line-by-line reading | Full comprehension of every log entry |
| `grep "198.51.100.23" auth.log` | Filter all entries from attacker IP |
| `grep "Accepted" auth.log` | Find all successful logins |
| `grep "Failed" auth.log \| wc -l` | Count total failure attempts (48 found) |
| `grep "192.0.2.99" syslog.log` | Track all C2 server connections |
| `grep "EXECVE" syslog.log` | Find all command executions |
| `grep "IPTABLES-OUT" syslog.log` | Find all outbound network connections |
| Timestamp correlation (manual) | Cross-reference auth.log and syslog events |

---

## Key Statistics from Log Analysis

| Metric | Value |
|---|---|
| Total failed SSH login attempts | 48 |
| Unique usernames attempted | 20+ |
| Time from first probe to root shell | 32 minutes |
| Time from root shell to exit | ~3 minutes |
| C2 beacon executions captured | 3 (03:20, 03:30, 03:40) |
| Outbound packets to C2 during exfil | 3 (PSH+ACK × 2, FIN × 1) |
| Total incident duration (incl. re-entry) | ~3.5 hours |
| Legitimate logins from known users (10 Mar) | 10+ (all public-key, normal hours) |

---

*Log analysis by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
