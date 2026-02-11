#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Baseline Linux Hardening for: HTTP + FTP + DNS + MySQL/MariaDB
# - Supports: Debian/Ubuntu (apt), RHEL/Rocky/Alma/Fedora (dnf/yum)
# - Services: Apache (apache2/httpd) OR Nginx, vsftpd, bind9/named, mysql/mariadb
#
# Usage:
#   sudo bash secure_services.sh
# Optional:
#   DRY_RUN=1 sudo bash secure_services.sh
#   MYSQL_ALLOW_CIDR="10.0.0.0/8" sudo bash secure_services.sh
###############################################################################

# ---------- Operator toggles (safe defaults) ----------
: "${DRY_RUN:=0}"

# Firewall openings
: "${ALLOW_SSH:=1}"
: "${ALLOW_HTTP:=1}"      # 80/tcp
: "${ALLOW_HTTPS:=1}"     # 443/tcp
: "${ALLOW_FTP:=1}"       # 21/tcp (+ passive range)
: "${ALLOW_DNS:=1}"       # 53/tcp+udp
: "${ALLOW_MYSQL:=0}"     # 3306/tcp exposed? default NO

# If exposing MySQL, restrict to this CIDR (or "0.0.0.0/0" if you insist)
: "${MYSQL_ALLOW_CIDR:=127.0.0.1/32}"

# FTP passive port range (must match firewall + vsftpd config)
: "${FTP_PASV_MIN:=30000}"
: "${FTP_PASV_MAX:=31000}"

# FTP write access (uploads). Default off.
: "${FTP_ALLOW_WRITE:=0}"

# DNS role: "authoritative" (recursion off) or "resolver" (recursion on but restricted)
: "${DNS_ROLE:=authoritative}"
: "${DNS_RECURSION_ALLOW_CIDR:=127.0.0.1/32}"  # only relevant if DNS_ROLE=resolver

# SSH hardening (keep conservative to avoid lockouts)
: "${SSH_DISABLE_ROOT_LOGIN:=1}"
: "${SSH_PASSWORD_AUTH:=1}"  # set 0 to disable password auth (key-only) - can lock you out!

# ---------- Helpers ----------
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
die() { echo -e "[x] $*" >&2; exit 1; }

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY_RUN] $*"
  else
    eval "$@"
  fi
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    die "No supported package manager found (apt/dnf/yum)."
  fi
}

pkg_install() {
  local mgr="$1"; shift
  local pkgs=("$@")

  case "$mgr" in
    apt)
      run "DEBIAN_FRONTEND=noninteractive apt-get update -y"
      run "DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkgs[*]}"
      ;;
    dnf)
      run "dnf -y makecache"
      run "dnf -y install ${pkgs[*]}"
      ;;
    yum)
      run "yum -y makecache"
      run "yum -y install ${pkgs[*]}"
      ;;
  esac
}

enable_service() {
  local svc="$1"
  if systemctl list-unit-files | grep -qE "^${svc}\.service"; then
    run "systemctl enable --now ${svc} || true"
  fi
}

restart_service_if_exists() {
  local svc="$1"
  if systemctl list-unit-files | grep -qE "^${svc}\.service"; then
    run "systemctl restart ${svc} || true"
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  run "cp -a '$f' '${f}.bak.${ts}'"
}

file_has_line() {
  local f="$1" line="$2"
  [[ -f "$f" ]] && grep -qF -- "$line" "$f"
}

append_line_if_missing() {
  local f="$1" line="$2"
  if ! file_has_line "$f" "$line"; then
    run "printf '%s\n' '$line' >> '$f'"
  fi
}

chmod_with_fallback() {
  local perms="$1" primary="$2" fallback="$3"
  if [[ -f "$primary" ]]; then
    run "chmod $perms '$primary'" || {
      warn "Failed to chmod $primary, attempting fallback $fallback..."
      [[ -f "$fallback" ]] && run "chmod $perms '$fallback'" || warn "Neither $primary nor $fallback exist"
    }
  elif [[ -f "$fallback" ]]; then
    run "chmod $perms '$fallback'"
  else
    warn "Neither $primary nor $fallback exist"
  fi
}

# ...existing code...

###############################################################################
# Main Hardening Functions
###############################################################################

harden_ipv6() {
  log "Disabling IPv6..."
  cat > /etc/sysctl.d/99-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  run "sysctl -p /etc/sysctl.d/99-disable-ipv6.conf"
}

harden_filesystem() {
  log "Hardening filesystem permissions..."
  run "chmod 600 /etc/shadow"
  run "chmod 600 /etc/gshadow"
  run "chmod 644 /etc/passwd"
  run "chmod 644 /etc/group"
  chmod_with_fallback "600" "/etc/ssh/sshd_config" "/etc/ssh/ssh_config"
  
  cat > /etc/modprobe.d/disable-filesystems.conf <<'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF
}

harden_sysctl() {
  log "Hardening kernel parameters..."
  cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.yama.ptrace_scope = 2

# Network hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1

# DEP/ASLR
kernel.randomize_va_space = 2
EOF
  run "sysctl -p /etc/sysctl.d/99-hardening.conf"
}

harden_ssh() {
  log "Hardening SSH configuration..."
  backup_file "/etc/ssh/sshd_config"
  
  append_line_if_missing "/etc/ssh/sshd_config" "PermitRootLogin no"
  append_line_if_missing "/etc/ssh/sshd_config" "PasswordAuthentication no"
  append_line_if_missing "/etc/ssh/sshd_config" "PubkeyAuthentication yes"
  append_line_if_missing "/etc/ssh/sshd_config" "X11Forwarding no"
  append_line_if_missing "/etc/ssh/sshd_config" "MaxAuthTries 3"
  append_line_if_missing "/etc/ssh/sshd_config" "ClientAliveInterval 300"
  append_line_if_missing "/etc/ssh/sshd_config" "ClientAliveCountMax 2"
  append_line_if_missing "/etc/ssh/sshd_config" "Protocol 2"
  append_line_if_missing "/etc/ssh/sshd_config" "LogLevel VERBOSE"
  
  run "sshd -t || warn 'SSH config syntax error - check manually'"
  restart_service_if_exists "ssh"
}

harden_ufw_iptables() {
  log "Configuring UFW firewall with iptables backend for Ubuntu..."
  
  pkg_install "apt" ufw iptables
  
  run "ufw default deny incoming"
  run "ufw default allow outgoing"
  run "ufw default deny routed"
  
  # Essential services for OpenCart ecommerce
  [[ "$ALLOW_SSH" == "1" ]] && run "ufw allow 22/tcp comment 'SSH'"
  [[ "$ALLOW_HTTP" == "1" ]] && run "ufw allow 80/tcp comment 'HTTP'"
  [[ "$ALLOW_HTTPS" == "1" ]] && run "ufw allow 443/tcp comment 'HTTPS'"
  
  # MySQL - restrict to localhost only
  run "ufw allow from 127.0.0.1 to 127.0.0.1 port 3306 comment 'MariaDB local'"
  
  [[ "$ALLOW_DNS" == "1" ]] && run "ufw allow 53 comment 'DNS'"
  
  run "ufw enable"
  
  # Additional iptables rules for connection limiting
  log "Configuring iptables for connection limiting..."
  if [[ "$DRY_RUN" != "1" ]]; then
    # Limit new SSH connections to prevent brute force
    iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min --limit-burst 10 -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j DROP
    
    # Limit HTTP/HTTPS to prevent flood attacks
    iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/sec --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/sec --limit-burst 100 -j ACCEPT
    
    # Save rules
    run "iptables-save > /etc/iptables/rules.v4"
  fi
}

harden_apache2() {
  log "Hardening Apache2 for OpenCart..."
  
  pkg_install "apt" apache2 libapache2-mod-security2 modsecurity-crs
  
  backup_file "/etc/apache2/apache2.conf"
  
  # Disable unnecessary modules (only if they exist)
  run "a2dismod autoindex 2>/dev/null || true"
  run "a2dismod status 2>/dev/null || true"
  run "a2dismod info 2>/dev/null || true"
  
  # Enable security modules
  run "a2enmod rewrite 2>/dev/null || true"
  run "a2enmod headers 2>/dev/null || true"
  run "a2enmod ssl 2>/dev/null || true"
  run "a2enmod security2 2>/dev/null || true"
  
  # Harden Apache headers
  cat > /etc/apache2/conf-available/hardening.conf <<'EOF'
# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Disable TRACE method
TraceEnable Off

# Disable directory listing
<Directory />
  Options -Indexes -Includes -ExecCGI
  AllowOverride None
</Directory>
EOF
  run "a2enconf hardening 2>/dev/null || true"
  run "systemctl restart apache2 || true"
}

harden_modsecurity() {
  log "Configuring ModSecurity with OWASP CRS..."
  
  # Install OWASP CRS if not present
  if [[ ! -d "/usr/share/modsecurity-crs" ]]; then
    run "apt-get install -y modsecurity-crs 2>/dev/null || true"
  fi
  
  # Configure ModSecurity
  backup_file "/etc/modsecurity/modsecurity.conf"
  
  cat > /etc/modsecurity/modsecurity.conf <<'EOF'
# ModSecurity Main Configuration
SecRuleEngine On
SecAuditEngine On
SecAuditLog /var/log/modsecurity/modsec_audit.log
SecDebugLog /var/log/modsecurity/modsec_debug.log
SecDebugLogLevel 3
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecResponseBodyLimit 524288
SecResponseBodyMimeType application/json application/xml text/html text/plain
SecTmpDir /var/tmp/
SecDataDir /var/cache/modsecurity/
SecDefaultAction "phase:2,log,auditlog,deny,status:403"

# OWASP CRS
Include /etc/modsecurity/rules/OWASP-CRS/rules/*.conf
EOF
  
  # Enable OWASP CRS rules
  if [[ -d "/usr/share/modsecurity-crs" ]]; then
    log "Enabling OWASP ModSecurity Rules..."
    if [[ ! -d "/etc/modsecurity/rules/OWASP-CRS/rules" ]]; then
      run "mkdir -p /etc/modsecurity/rules"
      run "cp -r /usr/share/modsecurity-crs /etc/modsecurity/rules/OWASP-CRS"
    fi
  fi
  
  # Configure Apache to use ModSecurity
  cat > /etc/apache2/mods-available/security2.conf <<'EOF'
<IfModule mod_security2.c>
    MosSecurity Enable
    SecDebugLog /var/log/apache2/modsec_debug.log
    SecAuditLog /var/log/apache2/modsec_audit.log
    SecAuditLogFormat JSON

    # Logging
    SecAuditEngine On
    SecAuditLogRelevantStatus "^(?:4|5)"

    # Core rules
    SecRuleEngine On
    SecDefaultAction "phase:2,log,auditlog,deny,status:403"

    # Include OWASP CRS main rules
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/*.conf
</IfModule>
EOF
  
  run "mkdir -p /var/log/modsecurity /var/log/apache2"
  run "chown -R www-data:www-data /var/log/modsecurity /var/cache/modsecurity 2>/dev/null || true"
  
  run "systemctl restart apache2 || true"
}

harden_php() {
  log "Hardening PHP configuration for OpenCart..."
  
  pkg_install "apt" php php-mysql php-xml php-json php-gd php-curl php-mbstring php-zip
  
  # Find php.ini path
  local php_ini
  php_ini="$(php -r 'echo php_ini_loaded_file();' 2>/dev/null)" || php_ini="/etc/php/8.*/apache2/php.ini"
  
  if [[ -f "$php_ini" ]]; then
    backup_file "$php_ini"
    
    # Disable dangerous functions
    run "sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,proc_close,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' '$php_ini'"
    
    # Disable file uploads if not needed
    run "sed -i 's/^file_uploads.*/file_uploads = Off/' '$php_ini'"
    
    # Restrict execution to web root
    run "sed -i 's/^open_basedir.*/open_basedir = \\/var\\/www\\/html:.\\/tmp\\//' '$php_ini'"
    
    # Hide PHP version
    run "sed -i 's/^expose_php.*/expose_php = Off/' '$php_ini'"
    
    # Reduce max upload size
    run "sed -i 's/^upload_max_filesize.*/upload_max_filesize = 10M/' '$php_ini'"
    run "sed -i 's/^post_max_size.*/post_max_size = 10M/' '$php_ini'"
  fi
  
  run "systemctl restart apache2 || true"
}

harden_mariadb() {
  log "Hardening MariaDB..."
  
  pkg_install "apt" mariadb-server
  
  backup_file "/etc/mysql/mariadb.conf.d/50-server.cnf"
  
  cat >> /etc/mysql/mariadb.conf.d/50-server.cnf <<'EOF'

# Security hardening
skip-symbolic-links
skip-name-resolve
bind-address = 127.0.0.1

# Logging
log_error = /var/log/mysql/error.log
general_log = 0

# Enable binary logging for audit trail
log_bin = /var/log/mysql/mysql-bin.log
expire_logs_days = 7

# Disable local file access
local-infile = 0
EOF

  run "systemctl enable --now mariadb || true"
  
  # Remove default users and test database
  if [[ "$DRY_RUN" != "1" ]]; then
    log "Removing default MariaDB accounts..."
    mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1');" 2>/dev/null || true
    mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
  fi
}

harden_fail2ban() {
  log "Installing and configuring Fail2Ban..."
  
  pkg_install "apt" fail2ban
  
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 7200

[apache-auth]
enabled = true
port = http,https
logpath = %(apache_error_log)s
maxretry = 3
bantime = 1800

[apache-badbots]
enabled = true
port = http,https
logpath = %(apache_access_log)s
maxretry = 2
bantime = 1800

[apache-noscript]
enabled = true
port = http,https
logpath = %(apache_error_log)s
maxretry = 3
bantime = 1800

[apache-malicious-agents]
enabled = true
port = http,https
logpath = %(apache_access_log)s
maxretry = 2
bantime = 1800
EOF

  run "systemctl enable --now fail2ban || true"
  run "systemctl restart fail2ban || true"
}


harden_user_accounts() {
  log "Hardening user accounts..."
  
  run "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs"
  run "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs"
  run "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs"
  run "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs"
}

harden_auditd() {
  log "Installing and configuring auditd..."
  
  pkg_install "apt" auditd audispd-plugins
  
  cat > /etc/audit/rules.d/hardening.rules <<'EOF'
-D
-b 8192
-f 2

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S execve -F uid=0 -F auid>=1000 -F auid!=-1 -k admin_commands
-a always,exit -F arch=b32 -S execve -F uid=0 -F auid>=1000 -F auid!=-1 -k admin_commands
-w /var/www/html -p wa -k web_changes
-w /var/log/modsecurity -p wa -k modsec_logs

-e 2
EOF

  run "auditctl -R /etc/audit/rules.d/hardening.rules 2>/dev/null || true"
  run "systemctl enable --now auditd || true"
}

###############################################################################
# Main Execution
###############################################################################

main() {
  require_root
  
  log "=========================================="
  log "Ubuntu OpenCart Security Hardening"
  log "Apache2 + MariaDB + ModSecurity + Fail2Ban"
  log "=========================================="
  log "DRY_RUN=$DRY_RUN"
  
  local pkg_mgr
  pkg_mgr="$(detect_pkg_mgr)"
  log "Package manager: $pkg_mgr"
  
  # Core system hardening
  harden_ipv6
  harden_filesystem
  harden_sysctl
  harden_ssh
  harden_user_accounts
  
  # Network & firewall
  harden_ufw_iptables
  
  # Web application hardening
  harden_apache2
  harden_modsecurity
  harden_php
  
  # Database hardening
  harden_mariadb
  
  # Intrusion prevention
  harden_fail2ban
  
  
  # Logging & monitoring
  harden_auditd
  
  log "=========================================="
  log "✓ Hardening Complete!"
  log "=========================================="
  log ""
  log "IMMEDIATE ACTIONS REQUIRED:"
  log "1. Change OpenCart admin password NOW"
  log "2. Review firewall rules: ufw status verbose"
  log "3. Check ModSecurity logs: tail -f /var/log/apache2/modsec_audit.log"
  log "4. Check Fail2Ban status: fail2ban-client status"
  log "5. Review audit logs: tail -f /var/log/audit/audit.log"
  log ""
  [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN mode: No changes were made"
}

main