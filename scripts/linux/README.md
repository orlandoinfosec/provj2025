Installation Commands for Missing Tools:
---------------------------------------------
CentOS/RHEL:
bash# CentOS 7/8/Stream, RHEL 7/8/9
sudo yum install net-tools lsof psmisc procps-ng coreutils findutils
# Or for newer versions:
sudo dnf install net-tools lsof psmisc procps-ng coreutils findutils

Debian/Ubuntu:
bashsudo apt update
sudo apt install net-tools lsof psmisc procps coreutils findutils
Usage on CentOS:

bash# Save script as linux_baseline_forensics.sh
chmod +x linux_baseline_forensics.sh

# Run with default output location
sudo ./linux_baseline_forensics.sh

# Run with custom output directory  
sudo ./linux_baseline_forensics.sh /path/to/evidence/directory

----

✅ Distribution Detection:

Added automatic detection of RHEL vs Debian systems
Uses multiple methods (/etc/redhat-release, /etc/debian_version, /etc/os-release)

✅ System Information Collection:

Added SELinux status collection for RHEL/CentOS
Added AppArmor status for Debian/Ubuntu
Made timedatectl optional (older systems might not have it)
Added CentOS/RHEL specific release files

✅ Network Information:

Added firewalld support for CentOS/RHEL
Fallback to ip neigh if arp command is not available
Distribution-specific firewall rule collection

✅ Log Collection:

CentOS/RHEL: /var/log/secure, /var/log/messages, /var/log/maillog, /var/log/httpd
Debian/Ubuntu: /var/log/auth.log, /var/log/syslog, /var/log/mail.log, /var/log/apache2
Added package manager logs (yum.log/dnf.log vs dpkg.log/apt)

✅ Configuration Collection:

Added chkconfig support for legacy CentOS systems
CentOS-specific config files (/etc/sysconfig/)
Different cron directory handling
Package management log collection

✅ Timeline Creation:

RPM package history for RHEL systems
DEB package history for Debian systems
Distribution-specific log analysis

✅ Command Availability:

Added package installation suggestions
Better error handling for missing commands

Key CentOS/RHEL Compatibility Features Added:

Service Management: Both systemctl (modern) and chkconfig (legacy)
Firewall: firewalld + iptables support
Logs: Proper RHEL log file locations
Security: SELinux status collection
Packages: RPM/YUM/DNF package tracking
SSH Service: Correct systemd unit names (sshd vs ssh)



The script now properly handles:

✅ CentOS 7, 8, Stream
✅ RHEL 7, 8, 9
✅ Rocky Linux, AlmaLinux
✅ Debian 9, 10, 11, 12
✅ Ubuntu 18.04, 20.04, 22.04, 24.04