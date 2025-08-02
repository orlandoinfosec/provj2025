## 🐧 **Runbook 1 – Linux: Detecting Malware Persistence**

**Objective**
Identify Linux persistence methods (cron, systemd, rc.local, shell profiles).

**Tools Required**
`cron`, `systemctl`, `find`, `grep`, `cat`, `ls`, optionally `auditd`

**Download / Install**

* `cron`, `systemctl`, `find`, `grep` included in standard Linux.
* For `netstat`, `lsof`, install via package manager:

  ```bash
  sudo apt-get update && sudo apt-get install net-tools lsof
  ```

  ([Sysdig][1])

**Step-by-Step Instructions**

1. **User/system cron jobs**

   ```bash
   crontab -l
   sudo ls -al /var/spool/cron/
   sudo cat /etc/crontab
   sudo ls -al /etc/cron.d/ /etc/cron.daily/
   ```

   → Suspicious scheduled commands, URLs or base64.

2. **Systemd services**

   ```bash
   systemctl list-units --type=service --all
   sudo ls -al /etc/systemd/system/
   sudo cat /etc/systemd/system/<service>.service
   ```

   → Hidden service units, scripts in `/tmp`, `/home`.

3. **Legacy init scripts**

   ```bash
   sudo ls -l /etc/init.d/
   sudo chkconfig --list
   ```

   → Older servers use `/etc/init.d`.

4. **Shell profiles**

   ```bash
   cat ~/.bashrc ~/.bash_profile ~/.profile
   ```

   → Look for commands invoking scripts or binary payloads.

5. **rc.local script**

   ```bash
   sudo cat /etc/rc.local
   ```

   → Startup commands, especially non-root created.

6. **Script scanning**

   ```bash
   sudo find / -type f -name "*.sh" -exec grep -HiE "curl|wget|base64|nc|bash" {} \; 2>/dev/null
   ```

   → Downloader scripts or obfuscated launchers.

**What to Look For / IOCs**

* Cron entries calling external endpoints or obfuscated.
* `.service` files pointing to scripts in unusual dirs.
* Login profiles launching reverse‑shell code.
* Scripts referencing remote payloads or base64‑decoded runners.