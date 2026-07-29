# 🔄 Incident Response Workflow
### NIST SP 800-61 Applied — webserver01 Compromise | 10 March 2024

---

## Phase 1 — Detection

**Triggered:** 03:14 AM (attack start) | Identified: During retrospective log analysis

### What Should Have Triggered Alerts:
- SSH brute-force Rule-01 fires at **03:14:07** — 10 failures from 198.51.100.23 within seconds
- Invalid username enumeration Rule-02 fires at **03:14:35**
- Outbound connection to unknown IP Rule-09 fires at **03:20:05** (first IPTABLES-OUT to 192.0.2.99)
- C2 cron pattern Rule-12 fires at **03:30:06** (second consecutive execution)

### Why Detection Was Delayed:
- fail2ban was not configured or had thresholds too high
- No SIEM correlation between auth.log failures and syslog outbound connections
- No real-time alerting on outbound connections to non-approved IPs
- Auditd was not capturing EXECVE events for all users

### Detection Improvement Actions:
```
✔  Deploy fail2ban — ban after 5 failures in 60 seconds, 1-hour minimum ban
✔  Forward auth.log and syslog to centralised SIEM in real time
✔  Create correlation rule: SSH failure spike + outbound connection = CRITICAL alert
✔  Configure auditd EXECVE logging for all users
```

---

## Phase 2 — Triage & Alert

**Timing:** Immediately upon detection

### Classification: CRITICAL
**Rationale:** Confirmed intrusion chain — brute-force → successful login → privilege escalation → backdoor → data exfiltration → C2 active

### Notifications:
```
1. Tier 2 SOC Analyst — immediate
2. Security Manager On-Call — immediate
3. System Owner (webserver01) — within 15 minutes
4. CISO — within 30 minutes (data exfiltration confirmed)
5. Data Protection Officer — within 1 hour (potential data breach)
```

### Initial Ticket:
```
INCIDENT: webserver01 — Active Compromise
SEVERITY: CRITICAL (P1)
OPENED:   10 March 2024, 03:14 (retroactive) / [detection time] (actual)
SOURCE IP: 198.51.100.23
C2 IP:     192.0.2.99
ACCOUNTS:  backup (compromised), sysupdate (backdoor)
STATUS:    Investigation in progress
```

---

## Phase 3 — Investigation

**Method:** Log correlation — auth.log + syslog.log

### Investigation Steps Performed:
1. Establish clean baseline from 09 March activity
2. Identify first anomalous event — 03:14:02 brute-force start
3. Correlate syslog IPTABLES-OUT logs with auth.log SSH events
4. Map privilege escalation chain: backup → sudo → root shell
5. Identify all persistence mechanisms: sysupdate account + cron job
6. Confirm data staging and exfiltration via syslog EXECVE + IPTABLES FIN
7. Document anti-forensics activity: bash_history wipe
8. Identify backdoor re-entry at 06:03:19
9. Extract all IOCs: attacker IPs, C2 server, malicious commands, accounts

### Evidence Preserved:
```
✔  auth.log — full copy before any remediation
✔  syslog.log — full copy before any remediation
✔  /tmp/.cache_bkp.tar.gz — staged archive (hash: [SHA256 to be recorded])
✔  /etc/sudoers — screenshot/copy of malicious NOPASSWD entry
✔  root crontab — copy of malicious cron entry
✔  IPTABLES logs — outbound connection records
```

---

## Phase 4 — Containment

**Priority:** Immediate — C2 channel still active

### Short-Term Containment (do immediately, even if server must stay online):

```bash
# 1. Block attacker IPs at host firewall
iptables -A INPUT  -s 198.51.100.23 -j DROP
iptables -A OUTPUT -d 198.51.100.23 -j DROP
iptables -A OUTPUT -d 192.0.2.99    -j DROP

# 2. Kill any active attacker sessions
who                           # identify active sessions
pkill -KILL -u backup         # kill backup user sessions
pkill -KILL -u sysupdate      # kill sysupdate sessions

# 3. Lock compromised accounts
passwd -l backup
passwd -l sysupdate

# 4. Remove malicious cron (stop C2 beacon)
crontab -l -u root            # view root crontab
crontab -e -u root            # remove malicious entry
```

### Long-Term Containment (if possible):
- Take server offline for forensic imaging
- Restore from last known-clean snapshot
- Block 198.51.100.23 and 192.0.2.99 at network perimeter/security group

---

## Phase 5 — Eradication

**Goal:** Remove every attacker foothold from the system

```bash
# Remove backdoor account
userdel -r sysupdate
grep sysupdate /etc/passwd    # confirm removed
grep sysupdate /etc/shadow    # confirm removed
grep sysupdate /etc/sudoers   # confirm removed

# Revert /etc/sudoers to known-good
cp /etc/sudoers.bak /etc/sudoers   # restore from backup
visudo -c                           # validate syntax

# Remove malicious cron
crontab -r -u root            # remove all root cron entries
# OR selectively edit:
crontab -e -u root            # remove only the malicious line

# Check ALL cron locations
cat /etc/crontab
ls /etc/cron.d/
ls /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/
ls /var/spool/cron/crontabs/

# Remove staged archive
sha256sum /tmp/.cache_bkp.tar.gz   # hash for evidence first
rm /tmp/.cache_bkp.tar.gz

# Check for other persistence mechanisms
find / -name "*.sh" -newer /var/log/auth.log -type f 2>/dev/null
find /etc -name "*.conf" -newer /var/log/auth.log 2>/dev/null
cat /root/.ssh/authorized_keys     # check for added SSH keys
cat /home/backup/.ssh/authorized_keys

# Check for installed malware/backdoors
systemctl list-units --type=service --state=running
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
```

---

## Phase 6 — Recovery

**Goal:** Restore to a secure, verified operational state

```bash
# Harden SSH configuration
vi /etc/ssh/sshd_config
# Set:
#   PasswordAuthentication no
#   PermitRootLogin no
#   MaxAuthTries 3
#   LoginGraceTime 20
#   AllowUsers deploy aritra ubuntu    # whitelist only legitimate users
systemctl restart ssh

# Rotate all secrets in web application
# - Database passwords in /var/www/html config files
# - API keys and tokens
# - nginx basic auth credentials
# - SSL private keys if exposed in /etc/nginx

# Re-enable server with monitoring
systemctl start fail2ban
systemctl enable fail2ban

# Verify system integrity
aide --init          # initialise AIDE file integrity database
aide --check         # compare against known-good state

# Monitor for 72 hours post-recovery
tail -f /var/log/auth.log | grep "198.51.100"   # watch for return
```

---

## Phase 7 — Post-Incident Review

**Timing:** Within 5 business days of resolution

### Lessons Learned:
1. **fail2ban was absent or misconfigured** — 40+ brute-force attempts should have triggered an automatic ban within 2 minutes
2. **Service account "backup" had sudo privileges** — direct violation of principle of least privilege
3. **Password authentication was enabled for service accounts** — all service accounts should use key-based auth only
4. **No real-time SIEM correlation** — the C2 cron firing at 03:20 should have alerted before the intrusion was confirmed
5. **No egress filtering** — outbound connection to 192.0.2.99 should have been blocked before exfiltration
6. **Evidence tampering succeeded partially** — bash_history was cleared; auditd EXECVE would have preserved the full command record

### Action Items:
```
[ ] Deploy and configure fail2ban with aggressive thresholds
[ ] Audit ALL service accounts — remove sudo from non-admin accounts
[ ] Set PasswordAuthentication no in /etc/ssh/sshd_config
[ ] Deploy Wazuh or Elastic SIEM with real-time correlation rules
[ ] Implement egress firewall — only approved outbound IPs
[ ] Enable auditd EXECVE logging for all users
[ ] Configure immutable remote syslog forwarding
[ ] Implement AIDE or Wazuh FIM for /etc/sudoers, /etc/cron*, /etc/passwd
[ ] Deploy weekly automated account baseline comparison
[ ] Conduct post-incident tabletop exercise with the security team
```

---

*Workflow documented by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
