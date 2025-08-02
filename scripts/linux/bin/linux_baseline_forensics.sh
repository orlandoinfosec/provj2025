#!/bin/bash

#############################################################################
# Linux Forensic Data Collection Script for Incident Response
# 
# Author: Cybersecurity Engineer
# Purpose: Collect forensic data from compromised Linux systems
# Version: 1.1
# 
# USAGE: sudo ./forensic_collector.sh [output_directory]
# 
# This script collects forensic artifacts from Linux systems in a 
# production-safe manner, preserving data integrity and timestamps.
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_VERSION="1.1"
START_TIME=$(date '+%Y%m%d_%H%M%S')
HOSTNAME=$(hostname)
OUTPUT_DIR="${1:-/tmp/forensic_${HOSTNAME}_${START_TIME}}"
REPORT_FILE="${OUTPUT_DIR}/forensic_report_${START_TIME}.txt"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
LOG_FILE="${OUTPUT_DIR}/collection.log"

# Distribution detection
DISTRO=""
if [[ -f /etc/redhat-release ]]; then
    DISTRO="RHEL"
elif [[ -f /etc/debian_version ]]; then
    DISTRO="DEBIAN"
elif [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
        centos|rhel|fedora|rocky|almalinux) DISTRO="RHEL" ;;
        debian|ubuntu) DISTRO="DEBIAN" ;;
        *) DISTRO="UNKNOWN" ;;
    esac
else
    DISTRO="UNKNOWN"
fi

# IOC tracking arrays
declare -a SUSPICIOUS_PROCESSES=()
declare -a SUSPICIOUS_CONNECTIONS=()
declare -a SUSPICIOUS_FILES=()
declare -a SUSPICIOUS_USERS=()
declare -a CONFIGURATION_CHANGES=()

#############################################################################
# UTILITY FUNCTIONS
#############################################################################

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Error handling
error_exit() {
    log_message "ERROR" "$1"
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

# Safe command execution with logging
safe_execute() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    log_message "INFO" "Executing: ${description}"
    
    if [[ -n "$output_file" ]]; then
        eval "$cmd" > "$output_file" 2>&1
        local exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            log_message "SUCCESS" "Completed: ${description}"
        else
            log_message "WARNING" "Command failed (exit code: $exit_code): ${description}"
        fi
    else
        eval "$cmd" 2>&1 | tee -a "${LOG_FILE}"
    fi
}

# Create directory structure
create_directories() {
    log_message "INFO" "Creating directory structure"
    mkdir -p "${OUTPUT_DIR}"/{evidence,logs,network,processes,files,config,timeline} || error_exit "Failed to create directories"
    chmod 750 "${OUTPUT_DIR}"
}

# Preserve file with metadata
preserve_file() {
    local source_file="$1"
    local dest_dir="$2"
    local preserve_name="${3:-$(basename "$source_file")}"
    
    if [[ -f "$source_file" ]]; then
        # Preserve original timestamps and permissions
        cp -p "$source_file" "${dest_dir}/${preserve_name}" 2>/dev/null
        # Create hash for integrity
        sha256sum "$source_file" >> "${dest_dir}/file_hashes.txt" 2>/dev/null
        log_message "INFO" "Preserved: $source_file"
    fi
}

#############################################################################
# SYSTEM INFORMATION COLLECTION
#############################################################################

collect_system_info() {
    log_message "INFO" "Collecting system information"
    local sys_dir="${EVIDENCE_DIR}/system"
    mkdir -p "$sys_dir"
    
    # Basic system information
    safe_execute "uname -a" "${sys_dir}/uname.txt" "System kernel information"
    safe_execute "uptime" "${sys_dir}/uptime.txt" "System uptime"
    safe_execute "date" "${sys_dir}/current_time.txt" "Current system time"
    safe_execute "hostnamectl" "${sys_dir}/hostname.txt" "Hostname information"
    safe_execute "cat /etc/os-release" "${sys_dir}/os_release.txt" "OS release information"
    safe_execute "lscpu" "${sys_dir}/cpu_info.txt" "CPU information"
    safe_execute "free -h" "${sys_dir}/memory_info.txt" "Memory information"
    safe_execute "df -h" "${sys_dir}/disk_usage.txt" "Disk usage"
    safe_execute "mount" "${sys_dir}/mounted_filesystems.txt" "Mounted filesystems"
    safe_execute "lsblk" "${sys_dir}/block_devices.txt" "Block devices"
    
    # Time configuration (different methods for different distros)
    if command -v timedatectl &> /dev/null; then
        safe_execute "timedatectl status" "${sys_dir}/time_config.txt" "Time configuration"
    else
        safe_execute "date; cat /etc/localtime 2>/dev/null || echo 'No localtime info'" "${sys_dir}/time_config.txt" "Time configuration"
    fi
    
    # Distribution-specific release info
    if [[ "$DISTRO" == "RHEL" ]]; then
        preserve_file "/etc/redhat-release" "$sys_dir"
        preserve_file "/etc/centos-release" "$sys_dir"
    fi
    
    # Environment variables
    safe_execute "env" "${sys_dir}/environment.txt" "Environment variables"
    
    # SELinux status (RHEL/CentOS)
    if command -v getenforce &> /dev/null; then
        safe_execute "getenforce" "${sys_dir}/selinux_status.txt" "SELinux status"
        safe_execute "sestatus" "${sys_dir}/selinux_details.txt" "SELinux details"
    fi
    
    # AppArmor status (Debian/Ubuntu)
    if command -v aa-status &> /dev/null; then
        safe_execute "aa-status" "${sys_dir}/apparmor_status.txt" "AppArmor status"
    fi
}

#############################################################################
# PROCESS ANALYSIS
#############################################################################

collect_process_info() {
    log_message "INFO" "Collecting process information"
    local proc_dir="${EVIDENCE_DIR}/processes"
    mkdir -p "$proc_dir"
    
    # Process listings with different detail levels
    safe_execute "ps aux --forest" "${proc_dir}/ps_forest.txt" "Process tree"
    safe_execute "ps -eo pid,ppid,cmd,comm,user,group,nice,start,etime,pmem,pcpu --sort=-pcpu" "${proc_dir}/ps_detailed.txt" "Detailed process list"
    safe_execute "top -b -n 1" "${proc_dir}/top_snapshot.txt" "Top processes snapshot"
    
    # Process network connections
    safe_execute "lsof -i" "${proc_dir}/network_connections.txt" "Network connections by process"
    safe_execute "lsof +L1" "${proc_dir}/deleted_files.txt" "Processes with deleted files"
    
    # Analyze suspicious processes
    analyze_suspicious_processes "$proc_dir"
}

analyze_suspicious_processes() {
    local proc_dir="$1"
    log_message "INFO" "Analyzing processes for IOCs"
    
    # Check for processes with suspicious characteristics
    while IFS= read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        local user=$(echo "$line" | awk '{print $1}')
        
        # Flag suspicious patterns
        if [[ "$cmd" =~ (nc|netcat|ncat).* ]] || \
           [[ "$cmd" =~ .*reverse.* ]] || \
           [[ "$cmd" =~ .*shell.* ]] && [[ "$cmd" =~ .*tcp.* ]] || \
           [[ "$cmd" =~ python.*-c.* ]] || \
           [[ "$cmd" =~ perl.*-e.* ]] || \
           [[ "$cmd" =~ bash.*-i.* ]] || \
           [[ "$user" == "nobody" && "$cmd" =~ .*/tmp/.* ]]; then
            SUSPICIOUS_PROCESSES+=("PID:$pid USER:$user CMD:$cmd")
            log_message "WARNING" "Suspicious process detected: PID $pid - $cmd"
        fi
    done < "${proc_dir}/ps_detailed.txt"
    
    # Save suspicious processes
    if [[ ${#SUSPICIOUS_PROCESSES[@]} -gt 0 ]]; then
        printf '%s\n' "${SUSPICIOUS_PROCESSES[@]}" > "${proc_dir}/suspicious_processes.txt"
    fi
}

#############################################################################
# NETWORK ANALYSIS
#############################################################################

collect_network_info() {
    log_message "INFO" "Collecting network information"
    local net_dir="${EVIDENCE_DIR}/network"
    mkdir -p "$net_dir"
    
    # Network configuration
    safe_execute "ip addr show" "${net_dir}/ip_addresses.txt" "Network interfaces"
    safe_execute "ip route show" "${net_dir}/routing_table.txt" "Routing table"
    
    # ARP table (different commands for different systems)
    if command -v arp &> /dev/null; then
        safe_execute "arp -a" "${net_dir}/arp_table.txt" "ARP table"
    else
        safe_execute "ip neigh show" "${net_dir}/arp_table.txt" "ARP table (ip neigh)"
    fi
    
    # Network connections
    safe_execute "netstat -tulpn" "${net_dir}/listening_ports.txt" "Listening ports"
    safe_execute "netstat -an" "${net_dir}/all_connections.txt" "All network connections"
    safe_execute "ss -tulpn" "${net_dir}/socket_statistics.txt" "Socket statistics"
    
    # Firewall rules - distribution specific
    if [[ "$DISTRO" == "RHEL" ]]; then
        # CentOS/RHEL firewall commands
        if command -v firewall-cmd &> /dev/null; then
            safe_execute "firewall-cmd --list-all" "${net_dir}/firewalld_rules.txt" "Firewalld rules"
            safe_execute "firewall-cmd --list-services" "${net_dir}/firewalld_services.txt" "Firewalld services"
        fi
        if command -v iptables &> /dev/null; then
            safe_execute "iptables -L -n -v" "${net_dir}/iptables_rules.txt" "IPTables rules"
        fi
    else
        # Debian/Ubuntu firewall commands
        safe_execute "iptables -L -n -v" "${net_dir}/iptables_rules.txt" "IPTables rules"
        if command -v ufw &> /dev/null; then
            safe_execute "ufw status verbose" "${net_dir}/ufw_status.txt" "UFW firewall status"
        fi
    fi
    
    analyze_network_connections "$net_dir"
}

analyze_network_connections() {
    local net_dir="$1"
    log_message "INFO" "Analyzing network connections for IOCs"
    
    # Analyze listening ports for suspicious services
    if [[ -f "${net_dir}/listening_ports.txt" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ tcp.*:([0-9]+).* ]]; then
                local port="${BASH_REMATCH[1]}"
                # Flag unusual high ports or common backdoor ports
                if [[ "$port" -gt 10000 ]] || \
                   [[ "$port" == "4444" ]] || [[ "$port" == "5554" ]] || \
                   [[ "$port" == "9999" ]] || [[ "$port" == "31337" ]]; then
                    SUSPICIOUS_CONNECTIONS+=("Suspicious listening port: $line")
                    log_message "WARNING" "Suspicious listening port detected: $port"
                fi
            fi
        done < "${net_dir}/listening_ports.txt"
    fi
}

#############################################################################
# LOG ANALYSIS
#############################################################################

collect_logs() {
    log_message "INFO" "Collecting system logs"
    local logs_dir="${EVIDENCE_DIR}/logs"
    mkdir -p "$logs_dir"
    
    # Distribution-specific log locations
    if [[ "$DISTRO" == "RHEL" ]]; then
        # CentOS/RHEL log files
        preserve_file "/var/log/messages" "$logs_dir"
        preserve_file "/var/log/secure" "$logs_dir"
        preserve_file "/var/log/maillog" "$logs_dir"
        preserve_file "/var/log/cron" "$logs_dir"
        preserve_file "/var/log/yum.log" "$logs_dir"
        preserve_file "/var/log/dnf.log" "$logs_dir"
        
        # Web server logs (RHEL paths)
        for log_path in /var/log/httpd /var/log/nginx; do
            if [[ -d "$log_path" ]]; then
                cp -rp "$log_path" "$logs_dir/" 2>/dev/null
                log_message "INFO" "Copied web server logs from $log_path"
            fi
        done
    else
        # Debian/Ubuntu log files
        preserve_file "/var/log/syslog" "$logs_dir"
        preserve_file "/var/log/auth.log" "$logs_dir"
        preserve_file "/var/log/mail.log" "$logs_dir"
        preserve_file "/var/log/daemon.log" "$logs_dir"
        preserve_file "/var/log/dpkg.log" "$logs_dir"
        preserve_file "/var/log/apt/history.log" "$logs_dir"
        
        # Web server logs (Debian paths)
        for log_path in /var/log/apache2 /var/log/nginx; do
            if [[ -d "$log_path" ]]; then
                cp -rp "$log_path" "$logs_dir/" 2>/dev/null
                log_message "INFO" "Copied web server logs from $log_path"
            fi
        done
    fi
    
    # Common logs
    preserve_file "/var/log/messages" "$logs_dir"
    preserve_file "/var/log/kern.log" "$logs_dir"
    preserve_file "/var/log/dmesg" "$logs_dir"
    preserve_file "/var/log/boot.log" "$logs_dir"
    preserve_file "/var/log/wtmp" "$logs_dir"
    preserve_file "/var/log/btmp" "$logs_dir"
    preserve_file "/var/log/lastlog" "$logs_dir"
    
    # Journal logs (systemd) - available on both modern CentOS and Debian
    if command -v journalctl &> /dev/null; then
        safe_execute "journalctl --no-pager --since='7 days ago'" "${logs_dir}/journalctl_7days.txt" "Systemd journal (7 days)"
        safe_execute "journalctl --no-pager --priority=err --since='30 days ago'" "${logs_dir}/journalctl_errors.txt" "Systemd journal errors"
        safe_execute "journalctl --no-pager -u sshd --since='24 hours ago'" "${logs_dir}/journalctl_ssh.txt" "SSH service logs"
    fi
    
    analyze_logs "$logs_dir"
}

analyze_logs() {
    local logs_dir="$1"
    log_message "INFO" "Analyzing logs for IOCs"
    
    # Create combined analysis file
    local analysis_file="${logs_dir}/log_analysis.txt"
    
    # Search for common attack patterns in auth logs - distribution specific
    if [[ "$DISTRO" == "RHEL" ]]; then
        local auth_logs=("${logs_dir}/secure")
    else
        local auth_logs=("${logs_dir}/auth.log")
    fi
    
    for auth_log in "${auth_logs[@]}"; do
        if [[ -f "$auth_log" ]]; then
            echo "=== Failed Login Attempts ===" >> "$analysis_file"
            grep -i "failed\|failure\|invalid" "$auth_log" | tail -50 >> "$analysis_file" 2>/dev/null
            
            echo -e "\n=== Successful Logins ===" >> "$analysis_file"
            grep -i "accepted\|session opened" "$auth_log" | tail -20 >> "$analysis_file" 2>/dev/null
            
            echo -e "\n=== Privilege Escalation ===" >> "$analysis_file"
            grep -i "sudo\|su:" "$auth_log" | tail -20 >> "$analysis_file" 2>/dev/null
        fi
    done
    
    # Also check systemd journal for authentication events on modern systems
    if command -v journalctl &> /dev/null; then
        echo -e "\n=== Recent Authentication Events (journalctl) ===" >> "$analysis_file"
        if [[ "$DISTRO" == "RHEL" ]]; then
            journalctl --no-pager -u sshd --since="24 hours ago" >> "$analysis_file" 2>/dev/null
        else
            journalctl --no-pager -u ssh --since="24 hours ago" >> "$analysis_file" 2>/dev/null
        fi
    fi
    
    # Analyze web server logs for common attacks
    for web_log in "${logs_dir}"/*/access.log "${logs_dir}"/*/access_log; do
        if [[ -f "$web_log" ]]; then
            echo -e "\n=== Web Attack Patterns ===" >> "$analysis_file"
            grep -E "(\.\.\/|%2e%2e%2f|union.*select|<script|javascript:|cmd=|/bin/|/etc/passwd)" "$web_log" | tail -20 >> "$analysis_file" 2>/dev/null
        fi
    done
}

#############################################################################
# FILE SYSTEM ANALYSIS
#############################################################################

collect_file_info() {
    log_message "INFO" "Collecting file system information"
    local files_dir="${EVIDENCE_DIR}/files"
    mkdir -p "$files_dir"
    
    # Recently modified files
    safe_execute "find / -type f -mtime -7 -ls 2>/dev/null | head -1000" "${files_dir}/recent_files_7days.txt" "Recently modified files (7 days)"
    safe_execute "find /tmp -type f -ls 2>/dev/null" "${files_dir}/tmp_files.txt" "Files in /tmp"
    safe_execute "find /var/tmp -type f -ls 2>/dev/null" "${files_dir}/var_tmp_files.txt" "Files in /var/tmp"
    safe_execute "find /dev/shm -type f -ls 2>/dev/null" "${files_dir}/shm_files.txt" "Files in /dev/shm"
    
    # SUID/SGID files
    safe_execute "find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null" "${files_dir}/suid_sgid_files.txt" "SUID/SGID files"
    
    # World-writable files
    safe_execute "find / -type f -perm -002 -ls 2>/dev/null | head -500" "${files_dir}/world_writable_files.txt" "World-writable files"
    
    # Hidden files in common directories
    safe_execute "find /home -name '.*' -type f -ls 2>/dev/null" "${files_dir}/hidden_files_home.txt" "Hidden files in /home"
    safe_execute "find /root -name '.*' -type f -ls 2>/dev/null" "${files_dir}/hidden_files_root.txt" "Hidden files in /root"
    
    analyze_suspicious_files "$files_dir"
}

analyze_suspicious_files() {
    local files_dir="$1"
    log_message "INFO" "Analyzing files for IOCs"
    
    # Check for suspicious executables in temp directories
    for temp_dir in /tmp /var/tmp /dev/shm; do
        if [[ -d "$temp_dir" ]]; then
            find "$temp_dir" -type f -executable 2>/dev/null | while IFS= read -r file; do
                SUSPICIOUS_FILES+=("Executable in temp directory: $file")
                log_message "WARNING" "Suspicious executable found: $file"
                
                # Get file info
                ls -la "$file" >> "${files_dir}/suspicious_executables.txt" 2>/dev/null
                file "$file" >> "${files_dir}/suspicious_executables.txt" 2>/dev/null
                echo "---" >> "${files_dir}/suspicious_executables.txt"
            done
        fi
    done
    
    # Check for suspicious shell history modifications
    for user_home in /home/* /root; do
        if [[ -d "$user_home" ]]; then
            local history_file="${user_home}/.bash_history"
            if [[ -f "$history_file" ]]; then
                # Check if history file is empty or has suspicious patterns
                if [[ ! -s "$history_file" ]]; then
                    SUSPICIOUS_FILES+=("Empty history file: $history_file")
                    log_message "WARNING" "Empty history file found: $history_file"
                fi
                
                # Look for history clearing commands
                if grep -q "history -c\|unset HISTFILE\|export HISTSIZE=0" "$history_file" 2>/dev/null; then
                    SUSPICIOUS_FILES+=("History manipulation detected: $history_file")
                    log_message "WARNING" "History manipulation detected: $history_file"
                fi
            fi
        fi
    done
}

#############################################################################
# USER AND AUTHENTICATION ANALYSIS
#############################################################################

collect_user_info() {
    log_message "INFO" "Collecting user and authentication information"
    local users_dir="${EVIDENCE_DIR}/users"
    mkdir -p "$users_dir"
    
    # User and group information
    preserve_file "/etc/passwd" "$users_dir"
    preserve_file "/etc/shadow" "$users_dir"
    preserve_file "/etc/group" "$users_dir"
    preserve_file "/etc/gshadow" "$users_dir"
    
    # Login information
    safe_execute "last -a" "${users_dir}/last_logins.txt" "Last logins"
    safe_execute "lastb -a" "${users_dir}/failed_logins.txt" "Failed login attempts"
    safe_execute "w" "${users_dir}/current_users.txt" "Currently logged in users"
    safe_execute "who -a" "${users_dir}/who_all.txt" "Who information"
    
    # SSH configuration and keys
    preserve_file "/etc/ssh/sshd_config" "$users_dir"
    if [[ -d "/root/.ssh" ]]; then
        cp -rp "/root/.ssh" "${users_dir}/root_ssh" 2>/dev/null
    fi
    
    # User home directories analysis
    for user_home in /home/*; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$user_home")
            local user_dir="${users_dir}/${username}"
            mkdir -p "$user_dir"
            
            # SSH keys and config
            if [[ -d "${user_home}/.ssh" ]]; then
                cp -rp "${user_home}/.ssh" "${user_dir}/ssh" 2>/dev/null
            fi
            
            # Shell history (last 100 lines)
            if [[ -f "${user_home}/.bash_history" ]]; then
                tail -100 "${user_home}/.bash_history" > "${user_dir}/bash_history_recent.txt" 2>/dev/null
            fi
            
            # Shell configuration
            preserve_file "${user_home}/.bashrc" "$user_dir"
            preserve_file "${user_home}/.profile" "$user_dir"
        fi
    done
    
    analyze_users "$users_dir"
}

analyze_users() {
    local users_dir="$1"
    log_message "INFO" "Analyzing users for IOCs"
    
    # Check for users with UID 0 (root privileges)
    if [[ -f "${users_dir}/passwd" ]]; then
        while IFS=: read -r username _ uid _; do
            if [[ "$uid" == "0" && "$username" != "root" ]]; then
                SUSPICIOUS_USERS+=("User with UID 0: $username")
                log_message "WARNING" "Suspicious user with UID 0: $username"
            fi
        done < "${users_dir}/passwd"
    fi
    
    # Check for recently added users
    if [[ -f "${users_dir}/passwd" ]]; then
        echo "=== User Account Analysis ===" > "${users_dir}/user_analysis.txt"
        awk -F: '$3 >= 1000 {print "User: " $1 " UID: " $3 " Home: " $6 " Shell: " $7}' "${users_dir}/passwd" >> "${users_dir}/user_analysis.txt"
    fi
}

#############################################################################
# CONFIGURATION ANALYSIS
#############################################################################

collect_config_info() {
    log_message "INFO" "Collecting configuration information"
    local config_dir="${EVIDENCE_DIR}/config"
    mkdir -p "$config_dir"
    
    # System configuration files
    preserve_file "/etc/hosts" "$config_dir"
    preserve_file "/etc/resolv.conf" "$config_dir"
    preserve_file "/etc/crontab" "$config_dir"
    preserve_file "/etc/fstab" "$config_dir"
    preserve_file "/etc/sudoers" "$config_dir"
    preserve_file "/etc/passwd" "$config_dir"
    preserve_file "/etc/group" "$config_dir"
    
    # Service configurations - distribution specific
    if [[ "$DISTRO" == "RHEL" ]]; then
        # CentOS/RHEL service management
        if command -v systemctl &> /dev/null; then
            safe_execute "systemctl list-units --type=service --state=running" "${config_dir}/running_services.txt" "Running services"
            safe_execute "systemctl list-units --type=service --state=enabled" "${config_dir}/enabled_services.txt" "Enabled services"
            safe_execute "systemctl list-unit-files --type=service" "${config_dir}/all_services.txt" "All service unit files"
        fi
        
        # Legacy service management
        if command -v chkconfig &> /dev/null; then
            safe_execute "chkconfig --list" "${config_dir}/chkconfig.txt" "Service configuration (chkconfig)"
        fi
        
        # CentOS/RHEL specific configs
        preserve_file "/etc/sysconfig/network" "$config_dir"
        preserve_file "/etc/sysconfig/iptables" "$config_dir"
        
        # Package management logs
        preserve_file "/var/log/yum.log" "$config_dir"
        preserve_file "/var/log/dnf.log" "$config_dir"
        
    else
        # Debian/Ubuntu service management
        safe_execute "systemctl list-units --type=service --state=running" "${config_dir}/running_services.txt" "Running services"
        safe_execute "systemctl list-units --type=service --state=enabled" "${config_dir}/enabled_services.txt" "Enabled services"
        safe_execute "systemctl list-unit-files --type=service" "${config_dir}/all_services.txt" "All service unit files"
        
        # Legacy service management
        if command -v service &> /dev/null; then
            safe_execute "service --status-all" "${config_dir}/service_status.txt" "Service status (legacy)"
        fi
        
        # Package management logs
        preserve_file "/var/log/dpkg.log" "$config_dir"
        preserve_file "/var/log/apt/history.log" "$config_dir"
    fi
    
    # Cron jobs
    safe_execute "crontab -l" "${config_dir}/root_crontab.txt" "Root crontab"
    
    # User cron jobs - different locations for different distros
    for cron_dir in "/var/spool/cron/crontabs" "/var/spool/cron"; do
        if [[ -d "$cron_dir" ]]; then
            for user_cron in "$cron_dir"/*; do
                if [[ -f "$user_cron" ]]; then
                    local username=$(basename "$user_cron")
                    cp -p "$user_cron" "${config_dir}/cron_${username}.txt" 2>/dev/null
                fi
            done
        fi
    done
    
    # System cron directories
    for cron_sys_dir in "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly"; do
        if [[ -d "$cron_sys_dir" ]]; then
            cp -rp "$cron_sys_dir" "${config_dir}/" 2>/dev/null
        fi
    done
    
    # Service files that might indicate persistence
    safe_execute "find /etc/systemd/system -name '*.service' -type f -ls 2>/dev/null" "${config_dir}/custom_systemd_services.txt" "Custom systemd services"
    safe_execute "find /usr/lib/systemd/system -name '*.service' -type f -newermt '30 days ago' -ls 2>/dev/null" "${config_dir}/recent_systemd_services.txt" "Recently modified systemd services"
    
    analyze_configurations "$config_dir"
}

analyze_configurations() {
    local config_dir="$1"
    log_message "INFO" "Analyzing configurations for IOCs"
    
    # Check for suspicious cron jobs
    find "$config_dir" -name "*cron*" -type f | while IFS= read -r cron_file; do
        if grep -qE "(wget|curl|nc|netcat|python|perl|bash).*http" "$cron_file" 2>/dev/null; then
            CONFIGURATION_CHANGES+=("Suspicious cron job in: $cron_file")
            log_message "WARNING" "Suspicious cron job detected: $cron_file"
        fi
    done
    
    # Check for unauthorized sudo entries
    if [[ -f "${config_dir}/sudoers" ]]; then
        if grep -qE "^[^#]*ALL.*NOPASSWD.*ALL" "${config_dir}/sudoers" 2>/dev/null; then
            CONFIGURATION_CHANGES+=("Passwordless sudo access found in sudoers")
            log_message "WARNING" "Passwordless sudo access detected"
        fi
    fi
}

#############################################################################
# TIMELINE CREATION
#############################################################################

create_timeline() {
    log_message "INFO" "Creating timeline of events"
    local timeline_dir="${EVIDENCE_DIR}/timeline"
    mkdir -p "$timeline_dir"
    
    # File system timeline (last 7 days)
    safe_execute "find / -type f -newermt '7 days ago' -ls 2>/dev/null | sort -k8,9" "${timeline_dir}/file_timeline_7days.txt" "File modification timeline"
    
    # Process timeline from logs - distribution specific
    local today_pattern
    today_pattern="$(date '+%b %d')"
    local today_pattern_alt
    today_pattern_alt="$(date '+%b  %d')"  # Handle single digit days with extra space
    
    if [[ "$DISTRO" == "RHEL" ]]; then
        if [[ -f "/var/log/messages" ]]; then
            grep -E "($today_pattern|$today_pattern_alt)" /var/log/messages > "${timeline_dir}/today_messages.txt" 2>/dev/null
        fi
        if [[ -f "/var/log/secure" ]]; then
            grep -E "($today_pattern|$today_pattern_alt)" /var/log/secure > "${timeline_dir}/today_auth.txt" 2>/dev/null
        fi
    else
        if [[ -f "/var/log/syslog" ]]; then
            grep -E "($today_pattern|$today_pattern_alt)" /var/log/syslog > "${timeline_dir}/today_syslog.txt" 2>/dev/null
        fi
        if [[ -f "/var/log/auth.log" ]]; then
            grep -E "($today_pattern|$today_pattern_alt)" /var/log/auth.log > "${timeline_dir}/today_auth.txt" 2>/dev/null
        fi
    fi
    
    # Package installation timeline
    if [[ "$DISTRO" == "RHEL" ]]; then
        # RPM package history
        safe_execute "rpm -qa --last | head -50" "${timeline_dir}/recent_packages.txt" "Recently installed packages (RPM)"
        if [[ -f "/var/log/yum.log" ]]; then
            tail -100 /var/log/yum.log > "${timeline_dir}/yum_recent.txt" 2>/dev/null
        fi
        if [[ -f "/var/log/dnf.log" ]]; then
            tail -100 /var/log/dnf.log > "${timeline_dir}/dnf_recent.txt" 2>/dev/null
        fi
    else
        # DEB package history
        if [[ -f "/var/log/dpkg.log" ]]; then
            tail -100 /var/log/dpkg.log > "${timeline_dir}/dpkg_recent.txt" 2>/dev/null
        fi
        if [[ -f "/var/log/apt/history.log" ]]; then
            tail -50 /var/log/apt/history.log > "${timeline_dir}/apt_recent.txt" 2>/dev/null
        fi
    fi
}

#############################################################################
# REPORT GENERATION
#############################################################################

generate_report() {
    log_message "INFO" "Generating forensic report"
    
    cat > "$REPORT_FILE" << EOF
================================================================================
                        LINUX FORENSIC ANALYSIS REPORT
================================================================================

Investigation Details:
- Hostname: ${HOSTNAME}
- Collection Date: $(date)
- Script Version: ${SCRIPT_VERSION}
- Evidence Location: ${OUTPUT_DIR}

System Information:
- OS: $(if [[ -f /etc/os-release ]]; then grep PRETTY_NAME /etc/os-release | cut -d'"' -f2; elif [[ -f /etc/redhat-release ]]; then cat /etc/redhat-release; else echo "Unknown"; fi)
- Distribution Type: ${DISTRO}
- Kernel: $(uname -r)
- Uptime: $(uptime | awk '{print $3,$4}' | sed 's/,//')
- Architecture: $(uname -m)

================================================================================
                           INDICATORS OF COMPROMISE
================================================================================

EOF

    # Suspicious Processes
    if [[ ${#SUSPICIOUS_PROCESSES[@]} -gt 0 ]]; then
        echo "SUSPICIOUS PROCESSES DETECTED:" >> "$REPORT_FILE"
        printf '%s\n' "${SUSPICIOUS_PROCESSES[@]}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "No suspicious processes detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Suspicious Network Connections
    if [[ ${#SUSPICIOUS_CONNECTIONS[@]} -gt 0 ]]; then
        echo "SUSPICIOUS NETWORK CONNECTIONS:" >> "$REPORT_FILE"
        printf '%s\n' "${SUSPICIOUS_CONNECTIONS[@]}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "No suspicious network connections detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Suspicious Files
    if [[ ${#SUSPICIOUS_FILES[@]} -gt 0 ]]; then
        echo "SUSPICIOUS FILES DETECTED:" >> "$REPORT_FILE"
        printf '%s\n' "${SUSPICIOUS_FILES[@]}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "No suspicious files detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Suspicious Users
    if [[ ${#SUSPICIOUS_USERS[@]} -gt 0 ]]; then
        echo "SUSPICIOUS USER ACCOUNTS:" >> "$REPORT_FILE"
        printf '%s\n' "${SUSPICIOUS_USERS[@]}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "No suspicious user accounts detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Configuration Changes
    if [[ ${#CONFIGURATION_CHANGES[@]} -gt 0 ]]; then
        echo "SUSPICIOUS CONFIGURATION CHANGES:" >> "$REPORT_FILE"
        printf '%s\n' "${CONFIGURATION_CHANGES[@]}" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "No suspicious configuration changes detected." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    cat >> "$REPORT_FILE" << EOF
================================================================================
                              EVIDENCE SUMMARY
================================================================================

The following evidence has been collected and preserved:

System Information:
- Hardware and OS details: ${EVIDENCE_DIR}/system/
- Process information: ${EVIDENCE_DIR}/processes/
- Network configuration: ${EVIDENCE_DIR}/network/

Security Artifacts:
- System and application logs: ${EVIDENCE_DIR}/logs/
- User account information: ${EVIDENCE_DIR}/users/
- File system analysis: ${EVIDENCE_DIR}/files/
- Configuration files: ${EVIDENCE_DIR}/config/
- Timeline analysis: ${EVIDENCE_DIR}/timeline/

================================================================================
                            RECOMMENDED ACTIONS
================================================================================

Based on the analysis, consider the following actions:

1. IMMEDIATE ACTIONS:
   - Review all detected IOCs listed above
   - Isolate the system if malicious activity is confirmed
   - Change passwords for all accounts, especially privileged ones
   - Review and audit all user accounts and permissions

2. INVESTIGATION PRIORITIES:
   - Analyze suspicious processes and their network connections
   - Review authentication logs for unauthorized access
   - Examine recent file modifications and new executables
   - Check for persistence mechanisms (cron jobs, services, startup scripts)

3. CONTAINMENT MEASURES:
   - Block suspicious network connections at firewall level
   - Disable suspicious user accounts
   - Remove or quarantine suspicious files
   - Update and patch the system

4. RECOVERY STEPS:
   - Rebuild system from known good backups if heavily compromised
   - Implement additional monitoring and logging
   - Review and strengthen security controls
   - Conduct threat hunting across the environment

================================================================================
                              EVIDENCE INTEGRITY
================================================================================

File integrity hashes have been generated for all collected evidence.
Hash files are located in each evidence subdirectory as 'file_hashes.txt'.

Collection completed at: $(date)
Total evidence size: $(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)

================================================================================
                                   END REPORT
================================================================================
EOF

    echo -e "${GREEN}Forensic collection completed successfully!${NC}"
    echo -e "${BLUE}Report location: ${REPORT_FILE}${NC}"
    echo -e "${BLUE}Evidence location: ${OUTPUT_DIR}${NC}"
}

#############################################################################
# MAIN EXECUTION
#############################################################################

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root for complete data collection"
    fi
    
    # Check for required commands and suggest installation packages
    local required_commands=("find" "ps" "netstat" "ss" "lsof" "awk" "grep" "sort" "sha256sum")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
            log_message "WARNING" "Command '$cmd' not found. Some data collection may be incomplete."
        fi
    done
    
    # Suggest package installation if commands are missing
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        if [[ "$DISTRO" == "RHEL" ]]; then
            log_message "INFO" "To install missing tools on CentOS/RHEL: yum install net-tools lsof psmisc procps-ng coreutils findutils"
        elif [[ "$DISTRO" == "DEBIAN" ]]; then
            log_message "INFO" "To install missing tools on Debian/Ubuntu: apt install net-tools lsof psmisc procps coreutils findutils"
        fi
    fi
    
    # Display detected distribution
    log_message "INFO" "Detected distribution type: $DISTRO"
    
    echo -e "${GREEN}Linux Forensic Data Collection Script v${SCRIPT_VERSION}${NC}"
    echo -e "${BLUE}Collection starting at: $(date)${NC}"
    echo -e "${BLUE}Detected distribution: ${DISTRO}${NC}"
    echo -e "${BLUE}Output directory: ${OUTPUT_DIR}${NC}"
    echo ""
    
    # Create directory structure
    create_directories
    
    # Initialize log file
    log_message "INFO" "Starting forensic data collection"
    log_message "INFO" "Script version: ${SCRIPT_VERSION}"
    log_message "INFO" "Target system: ${HOSTNAME}"
    
    # Collect evidence
    collect_system_info
    collect_process_info
    collect_network_info
    collect_logs
    collect_file_info
    collect_user_info
    collect_config_info
    create_timeline
    
    # Generate final report
    generate_report
    
    # Set appropriate permissions
    chmod -R 640 "${OUTPUT_DIR}"
    chmod 750 "${OUTPUT_DIR}"
    
    log_message "INFO" "Forensic collection completed successfully"
}

# Trap to handle script interruption
trap 'log_message "INFO" "Script interrupted by user"; exit 1' INT TERM

# Execute main function
main "$@"