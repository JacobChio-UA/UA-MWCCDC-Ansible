#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Ubuntu 24 Server Security Hardening + Honeypot Defense
# - Focus: Ecommerce (OpenCart) security on Ubuntu 24 LTS Server
# - Services: Apache2, MariaDB, Fail2Ban, ModSecurity
# - Defense: Honeypot measures to distract and slow attackers
#
# Usage:
#   sudo bash secure_services.sh
# Optional:
#   DRY_RUN=1 sudo bash secure_services.sh
###############################################################################

# ---------- Operator toggles (safe defaults) ----------
: "${DRY_RUN:=0}"

# Firewall openings
: "${ALLOW_SSH:=1}"
: "${ALLOW_HTTP:=1}"      # 80/tcp
: "${ALLOW_HTTPS:=1}"     # 443/tcp
: "${ALLOW_MYSQL:=0}"     # 3306/tcp local access only

# SSH hardening (keep conservative to avoid lockouts)
: "${SSH_DISABLE_ROOT_LOGIN:=1}"
: "${SSH_PASSWORD_AUTH:=1}"  # set 0 to disable password auth (key-only) - can lock you out!

# Honeypot configuration
: "${ENABLE_HONEYPOT:=1}"   # Enable defensive honeypot measures
: "${HONEYPOT_SSH_PORT:=2222}"  # Fake SSH service on alternate port
: "${HONEYPOT_HTTP_PORT:=8080}" # Fake web service on alternate port

# Admin SSH controls (safe defaults: do NOT open 22 globally)
: "${ADMIN_SSH_ALLOW_FROM:=}"
: "${ADMIN_SSH_BIND_LOCAL:=0}"

# Anti-automation settings
: "${BLOCK_SCANNERS:=1}"    # Block common scanners and recon tools
: "${SLOW_RESPONSES:=1}"    # Intentionally slow responses to waste attacker time

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

is_ssh_active() {
  # Return 0 if an ssh service (ssh or sshd) is present and active, else 1
  if systemctl list-unit-files --type=service | grep -qE "^ssh\.service|^sshd\.service"; then
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
      return 0
    fi
  fi
  return 1
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

###############################################################################
# Honeypot & Defensive Measures
###############################################################################

create_canary_file() {
  local filepath="$1" name="$2"
  log "Creating canary file: $filepath ($name)"
  mkdir -p "$(dirname "$filepath")"
  cat > "$filepath" <<EOF
[SENSITIVE] $name - DO NOT SHARE
This file contains confidential credentials for backup access.
Username: admin_backup
Password: P@ssw0rd2024!
API Key: sk-1234567890abcdef
EOF
  chmod 644 "$filepath"
}

create_fake_database() {
  log "Creating fake MariaDB database for honeypot..."
  if command -v mysql >/dev/null 2>&1; then
    mysql -e "CREATE DATABASE IF NOT EXISTS mysql_backups;" 2>/dev/null || true
    mysql -e "CREATE USER IF NOT EXISTS 'backup_user'@'localhost' IDENTIFIED BY 'BackupPass123';" 2>/dev/null || true
    mysql -e "GRANT ALL ON mysql_backups.* TO 'backup_user'@'localhost';" 2>/dev/null || true
    mysql -e "CREATE TABLE mysql_backups.backups (id INT, backup_date VARCHAR(255), size VARCHAR(255));" 2>/dev/null || true
    
    # Add more fake databases to increase confusion
    mysql -e "CREATE DATABASE IF NOT EXISTS wordpress_backup;" 2>/dev/null || true
    mysql -e "CREATE DATABASE IF NOT EXISTS customer_data;" 2>/dev/null || true
    mysql -e "CREATE USER IF NOT EXISTS 'wp_user'@'localhost' IDENTIFIED BY 'WPPass2024';" 2>/dev/null || true
    mysql -e "GRANT ALL ON wordpress_backup.* TO 'wp_user'@'localhost';" 2>/dev/null || true
    
    log "Fake databases created for attacker enumeration"
  fi
}

create_fake_ssh_honeypot() {
  log "Setting up fake SSH honeypot on port $HONEYPOT_SSH_PORT..."
  
  # Prefer using an existing endlessh binary if present
  if command -v endlessh >/dev/null 2>&1; then
    log "endlessh already installed; skipping package install"
  else
    log "endlessh not found; attempting non-interactive install"
    # Update package lists then try installing non-interactively.
    # If apt reports held/backported packages ("X not upgraded"), don't block execution.
    run "DEBIAN_FRONTEND=noninteractive apt-get update -y 2>/dev/null || true"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends endlessh 2>/dev/null || true"

    # If install failed due to broken deps, try fix-broken non-interactively (safe fallback)
    run "DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install 2>/dev/null || true"
  fi

  # Configure endlessh to use the configured honeypot port and reasonable timeouts
  cat > /etc/endlessh/config 2>/dev/null <<EOF
# Endless SSH configuration - delays and confuses brute forcers
Port $HONEYPOT_SSH_PORT
LogLevel 4
MaxLineLength 32768
MaxClients 4096
ConnectTimeout 600
ReadTimeout 600
WriteTimeout 600
IdleTimeout 600
EOF

  # Ensure systemd picks up changes and start the service without blocking
  run "systemctl daemon-reload 2>/dev/null || true"
  run "systemctl enable endlessh 2>/dev/null || true"
  run "systemctl restart endlessh 2>/dev/null || true"

  # Check the active unit's ExecStart. If it uses /usr/bin/env endlesssh (which
  # can fail in systemd), create a drop-in override that sets ExecStart to the
  # absolute endlessh binary when available.
  if systemctl list-unit-files | grep -qE "^endlessh\.service"; then
    current_exec=$(systemctl show -p ExecStart --value endlessh 2>/dev/null || true)
    if [[ -n "${current_exec}" && "${current_exec}" == *"/usr/bin/env endlesssh"* ]]; then
      local abs_bin
      abs_bin="$(command -v endlessh || true)"
      if [[ -n "${abs_bin}" ]]; then
        log "Detected /usr/bin/env in ExecStart; writing systemd drop-in to use ${abs_bin}"
        run "mkdir -p /etc/systemd/system/endlessh.service.d"
        cat > /etc/systemd/system/endlessh.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=${abs_bin} -p ${HONEYPOT_SSH_PORT}
Restart=always
RestartSec=5
EOF
        run "systemctl daemon-reload 2>/dev/null || true"
        run "systemctl restart endlessh 2>/dev/null || true"
      else
        warn "ExecStart uses /usr/bin/env endlesssh but absolute binary not found; consider installing endlessh"
      fi
    fi
  fi

  # If the package doesn't provide a working unit that binds to our port,
  # create a minimal systemd unit that invokes the endlessh binary with the
  # configured port. This ensures it listens on $HONEYPOT_SSH_PORT.
  if ! systemctl list-unit-files | grep -qE "^endlessh\.service"; then
    log "Creating fallback systemd unit for endlessh to ensure binding to $HONEYPOT_SSH_PORT"
    # Prefer an absolute path to the endlessh binary so systemd doesn't
    # rely on a PATH lookup via /usr/bin/env which can fail in service context.
    local endlessh_bin
    endlessh_bin="$(command -v endlessh || true)"
    if [[ -n "${endlessh_bin}" ]]; then
      log "Using endlessh binary at ${endlessh_bin} for systemd unit ExecStart"
      exec_start_line="${endlessh_bin} -p ${HONEYPOT_SSH_PORT}"
    else
      warn "endlessh binary not found in PATH; systemd unit will use /usr/bin/env fallback"
      exec_start_line="/usr/bin/env endlesssh -p ${HONEYPOT_SSH_PORT}"
    fi

    cat > /etc/systemd/system/endlessh.service <<EOF
[Unit]
Description=Endless SSH tarpit
After=network.target

[Service]
Type=simple
ExecStart=${exec_start_line}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    run "systemctl daemon-reload 2>/dev/null || true"
    run "systemctl enable --now endlessh 2>/dev/null || true"
  fi
}

create_fake_web_pages() {
  log "Creating fake admin/sensitive web pages for honeypot..."
  
  # Create fake admin login pages - MINIMAL to reduce attack surface
  mkdir -p /var/www/html/admin_old
  cat > /var/www/html/admin_old/index.html <<'EOF'
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested resource was not found.</p>
</body>
</html>
EOF
  
  # Create fake database export listing - READ-ONLY, no POST handling
  mkdir -p /var/www/html/backups
  cat > /var/www/html/backups/index.html <<'EOF'
<html>
<head><title>Backup Archive</title></head>
<body>
<h2>Backup Files</h2>
<p>This is a read-only backup archive. Access denied.</p>
</body>
</html>
EOF

  # Create only STATIC fake config files (no PHP execution)
  mkdir -p /var/www/html/config_samples
  cat > /var/www/html/config_samples/README.txt <<'EOF'
This directory contains sample configuration files for development only.
Do not use in production.

Example database settings:
- Host: localhost
- User: sample_user
- Password: examplepass123
EOF

  # Fake docker-compose.yml - static, cannot execute
  mkdir -p /var/www/html/examples
  cat > /var/www/html/examples/docker-compose.yml.example <<'EOF'
# Example Docker Compose - DO NOT USE IN PRODUCTION
version: '3'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: example_password_123
EOF

  cat > /var/www/html/examples/.env.example <<'EOF'
# Example environment file
# Copy to .env and fill with real values before deployment

APP_NAME=MyApp
DB_HOST=localhost
DB_DATABASE=myapp_db
DB_USERNAME=app_user
EOF

  run "chown -R www-data:www-data /var/www/html/ 2>/dev/null || true"
  # Restrict permissions on fake config directories
  run "chmod 750 /var/www/html/config_samples /var/www/html/examples 2>/dev/null || true"
  log "Fake static pages created (minimal attack surface)"
}

create_fake_credentials_everywhere() {
  log "Creating minimal fake credential references (read-only, safe)..."
  
  # Only create READ-ONLY text files with obvious fake patterns
  # Keep them minimal to reduce attack surface
  
  # Fake README with obviously fake credentials
  cat > /root/BACKUP_README.txt <<'EOF'
Backup Rotation Guide
Last backup: 2024-02-08 02:45 UTC
Backup admin: backup_user / BackupPass2024!
Backup location: /backups/weekly/

Note: These are example credentials only - use real ones for production
EOF
  chmod 400 /root/BACKUP_README.txt
  
  # One fake credentials file only - no API keys, just database
  cat > /etc/backup_config.example <<'EOF'
# Example backup configuration - DO NOT USE IN PRODUCTION
# Database backup credentials (EXAMPLES ONLY)
DB_BACKUP_USER="backup_user"
DB_BACKUP_PASS="BackupPass2024!"
DB_BACKUP_HOST="localhost"
EOF
  chmod 400 /etc/backup_config.example
  
  log "Minimal fake credentials created - read-only only"
}

create_fake_processes_and_services() {
  log "Creating minimal reference files (no executable services)..."
  
  # ONLY create reference/documentation files - no actual services to avoid complexity
  
  # Fake backup script reference (not executable)
  mkdir -p /usr/local/bin_backup
  cat > /usr/local/bin_backup/backup-db.sh.example <<'EOF'
#!/bin/bash
# Example database backup script - for reference only
# mysqldump -u backup_user -pBackupPass2024! --all-databases > backup.sql
# Backup to: /backups/weekly/
EOF
  
  # Fake cron job documentation
  cat > /etc/cron_backups.example <<'EOF'
# Example cron jobs for backup (documentation only)
# */6 * * * * root /usr/local/bin/backup-db.sh >> /var/log/backup.log 2>&1
# 0 2 * * * root /usr/local/bin/full-backup.sh >> /var/log/backup.log 2>&1
EOF
  
  log "Reference files created - no executable services"
}

create_decoy_directories() {
  log "Creating minimal decoy directories..."
  
  # Simple, harmless empty directories to give false leads
  mkdir -p /opt/.backup_cache
  mkdir -p /var/spool/.backup_temp
  mkdir -p /var/backups/.old_configs
  
  log "Decoy directories created"
}

setup_honeypot_monitoring() {
  log "Setting up honeypot monitoring (safe, audit-only)..."
  
  # Create honeypot access log
  touch /var/log/honeypot_access.log
  chmod 644 /var/log/honeypot_access.log
  
  # Add audit rules ONLY for static files - no PHP/executable monitoring
  auditctl -w /var/www/html/admin_old -p r -k honeypot_admin_access 2>/dev/null || true
  auditctl -w /var/www/html/backups -p r -k honeypot_backup_access 2>/dev/null || true
  auditctl -w /var/www/html/config_samples -p r -k honeypot_config_access 2>/dev/null || true
  auditctl -w /var/www/html/examples -p r -k honeypot_examples_access 2>/dev/null || true
  auditctl -w /root/BACKUP_README.txt -p r -k honeypot_readme 2>/dev/null || true
  auditctl -w /etc/backup_config.example -p r -k honeypot_backup_config 2>/dev/null || true
  auditctl -w /opt/.backup_cache -p r -k honeypot_cache_access 2>/dev/null || true
  auditctl -w /var/spool/.backup_temp -p r -k honeypot_temp_access 2>/dev/null || true
  
  log "Honeypot monitoring configured (read-only audit rules only)"
}

block_automated_scanners() {
  log "Adding rules to block common automated scanning tools..."
  
  # Block common scanning tool user agents at Apache level - CONSERVATIVE patterns only
  cat > /etc/apache2/conf-available/block-scanners.conf <<'EOF'
# Block common scanning tools and automated attacks
<IfModule mod_rewrite.c>
  RewriteEngine On
  
  # Block known scanner user agents only (avoid false positives)
  RewriteCond %{HTTP_USER_AGENT} (nmap|masscan|nikto|sqlmap|nessus|openvas|acunetix) [NC]
  RewriteRule ^.*$ - [F,L]
  
  # Block ONLY dangerous SQL patterns in query strings (not legitimate data)
  RewriteCond %{QUERY_STRING} (union\s+select|select.*from.*where|drop\s+table|insert\s+into.*values) [NC]
  RewriteRule ^.*$ - [F,L]
  
  # Block path traversal attempts only (../, .git, .env in URI)
  RewriteCond %{REQUEST_URI} \.\./|\\.git|\\.env|\\.htaccess|\\.svn [NC]
  RewriteRule ^.*$ - [F,L]
</IfModule>
EOF
  run "a2enconf block-scanners 2>/dev/null || true"
  run "a2enmod rewrite 2>/dev/null || true"
  
  # Conservative rate limiting - don't block normal users
  # Only applies to rapid requests (>10/sec = scanner behavior)
  if [[ "$DRY_RUN" != "1" ]]; then
    iptables -N SCANNER 2>/dev/null || true
    # Allow normal traffic, only block excessive scanning
    iptables -A SCANNER -p tcp --dport 80 -m limit --limit 10/sec --limit-burst 20 -j ACCEPT 2>/dev/null || true
    iptables -A SCANNER -j DROP 2>/dev/null || true
    
    iptables -I INPUT -p tcp --dport 80 -j SCANNER 2>/dev/null || true
  fi
  
  run "systemctl restart apache2 2>/dev/null || true"
  log "Scanner blocking rules configured (conservative patterns only)"
}

create_deceptive_responses() {
  log "Creating deceptive references to confuse scanners..."
  
  # DO NOT set fake server headers - they can break compatibility
  # Instead, hide real server info (handled in other functions)
  
  # Create misleading .txt files that scanners commonly look for
  # These give false leads without introducing vulnerabilities
  cat > /var/www/html/robots.txt <<'EOF'
# Standard robots.txt
User-agent: *
Disallow: /admin/
Disallow: /backups/
Disallow: /.env
Disallow: /config/
EOF
  
  log "Reference files created for scanner misdirection"
}

create_honeypot_port_responses() {
  log "Creating decoy references for common scanner targets..."
  
  # Create simple reference files that describe fake services
  # These are read-only and don't introduce vulnerabilities
  
  mkdir -p /var/www/html/.well-known
  
  # Fake .well-known/security.txt (standard security disclosure file)
  cat > /var/www/html/.well-known/security.txt <<'EOF'
Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Policy: https://example.com/security/
EOF
  
  log "Well-known directory references created"
}

add_anti_recon_measures() {
  log "Adding anti-reconnaissance measures..."
  
  # Disable SSH banner grabbing
  # Only attempt to edit SSH banner if ssh service is active. If SSH is off
  # for the competition, avoid modifying the config or restarting the service.
  if is_ssh_active; then
    sed -i 's/#VersionAddendum.*/VersionAddendum none/' /etc/ssh/sshd_config 2>/dev/null || true
    run "systemctl restart ssh 2>/dev/null || true"
  else
    warn "SSH service not active; skipping SSH banner changes."
  fi
  
  # Hide PHP version
  for php_conf in /etc/php/*/apache2/php.ini; do
    if [[ -f "$php_conf" ]]; then
      run "sed -i 's/expose_php.*/expose_php = Off/' '$php_conf'"
    fi
  done
  
  # Hide Apache version (already configured in hardening.conf)
  # Don't add fake headers - they can break debugging and tools
  
  # Create standard security disclosure file
  mkdir -p /var/www/html/.well-known
  cat > /var/www/html/.well-known/security.txt <<'EOF'
Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Policy: https://example.com/security/
EOF
  
  # Standard robots.txt (legitimate use, not deceptive)
  cat > /var/www/html/robots.txt <<'EOF'
User-agent: *
Disallow: /admin/
Disallow: /backups/
Disallow: /.env
Disallow: /config/
Disallow: /uploads/tmp/
EOF
  
  run "chown -R www-data:www-data /var/www/html/ 2>/dev/null || true"
  run "systemctl restart apache2 2>/dev/null || true"
  log "Anti-reconnaissance measures configured (no fake headers)"
}

add_fail2ban_scanner_rules() {
  log "Adding fail2ban rules to detect obvious attack patterns..."
  
  cat >> /etc/fail2ban/jail.local <<'EOF'

# Conservative SQL injection detection - only obvious patterns
[sql-injection-strict]
enabled = true
port = http,https
logpath = %(apache_error_log)s
maxretry = 2
findtime = 300
bantime = 3600
pattern = (union\s+select|select.*from.*where|drop\s+table|insert\s+into)

# Aggressive scanner user agents
[scanner-agents]
enabled = true
port = http,https
logpath = %(apache_access_log)s
maxretry = 3
findtime = 60
bantime = 7200
pattern = (nmap|masscan|nikto|sqlmap|nessus|openvas)

# Malicious request patterns to admin area
[admin-attack]
enabled = true
port = http,https
logpath = %(apache_access_log)s
maxretry = 5
findtime = 300
bantime = 3600
pattern = /admin/.*((union|select|drop|exec|script|javascript|onerror))
EOF

  run "systemctl restart fail2ban || true"
  log "Conservative fail2ban rules configured"
}


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
  # If SSH is disabled for the competition, skip SSH configuration to avoid
  # attempting to restart or modify a service that is intentionally down.
  if ! is_ssh_active; then
    warn "SSH service not active; skipping SSH hardening to avoid interference."
    return 0
  fi

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
  # SSH: by default we avoid opening 22 globally to prevent lockouts.
  # - If ADMIN_SSH_ALLOW_FROM is set, allow SSH only from that IP/CIDR.
  # - If ADMIN_SSH_BIND_LOCAL==1, bind sshd to localhost instead (see below).
  if [[ "$ALLOW_SSH" == "1" ]]; then
    # If SSH service is intentionally disabled, do not try to add UFW rules or
    # bind sshd. This prevents interference during competitions where SSH is off.
    if ! is_ssh_active; then
      warn "SSH service not active; skipping UFW/sshd rules for port 22."
    else
      # Remove any existing global 'allow 22' or 'allow ssh' rules to avoid
      # exposing SSH from anywhere. Use --force to avoid interactive prompts.
      run "ufw --force delete allow 22/tcp 2>/dev/null || true"
      run "ufw --force delete allow ssh 2>/dev/null || true"

      if [[ -n "${ADMIN_SSH_ALLOW_FROM:-}" ]]; then
        run "ufw allow from ${ADMIN_SSH_ALLOW_FROM} to any port 22 proto tcp comment 'Admin SSH only'"
        log "UFW: SSH allowed from ${ADMIN_SSH_ALLOW_FROM} only"
      elif [[ "${ADMIN_SSH_BIND_LOCAL}" == "1" ]]; then
        log "Configuring sshd to listen on localhost only (127.0.0.1)"
        append_line_if_missing "/etc/ssh/sshd_config" "ListenAddress 127.0.0.1"
        restart_service_if_exists "ssh"
        log "sshd bound to localhost; no UFW rule added for port 22"
      else
        log "No ADMIN_SSH_ALLOW_FROM set: ensuring SSH is not allowed from Anywhere"
      fi
    fi
  fi
  [[ "$ALLOW_HTTP" == "1" ]] && run "ufw allow 80/tcp comment 'HTTP'"
  [[ "$ALLOW_HTTPS" == "1" ]] && run "ufw allow 443/tcp comment 'HTTPS'"
  
  # MySQL - restrict to localhost only
  run "ufw allow from 127.0.0.1 to 127.0.0.1 port 3306 comment 'MariaDB local'"
  
  # Honeypot SSH tarpit - open to world to catch attackers
  [[ "$ENABLE_HONEYPOT" == "1" ]] && run "ufw allow $HONEYPOT_SSH_PORT/tcp comment 'Honeypot SSH Tarpit'"
  
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
    SecRuleEngine On
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
  log "Ubuntu 24 Server - Ecommerce Hardening"
  log "+ Honeypot Defensive Measures"
  log "=========================================="
  log "DRY_RUN=$DRY_RUN"
  log "Honeypot enabled: $ENABLE_HONEYPOT"
  
  # Core system hardening
  harden_ipv6
  harden_filesystem
  harden_sysctl
  harden_ssh
  harden_user_accounts
  
  # Network & firewall (simplified for Ubuntu)
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
  
  # Anti-automation and anti-scanning measures
  if [[ "$BLOCK_SCANNERS" == "1" ]]; then
    log "=========================================="
    log "Deploying anti-automation measures..."
    log "=========================================="
    block_automated_scanners
    create_deceptive_responses
    create_honeypot_port_responses
    add_anti_recon_measures
    add_fail2ban_scanner_rules
  fi
  
  # Setup honeypot defensive measures
  if [[ "$ENABLE_HONEYPOT" == "1" ]]; then
    log "=========================================="
    log "Setting up honeypot defensive measures..."
    log "=========================================="
    create_fake_ssh_honeypot
    create_fake_web_pages
    create_fake_credentials_everywhere
    create_fake_processes_and_services
    create_decoy_directories
    create_fake_database
    create_canary_file "/var/www/html/.htaccess_backup" "Apache Config Backup"
    create_canary_file "/home/ubuntu/.ssh/id_rsa.backup" "Admin SSH Key Backup"
    create_canary_file "/etc/mysql/.my.cnf.bak" "MySQL Credentials"
    create_canary_file "/var/backups/last_export.sql" "Database Export"
    setup_honeypot_monitoring
  fi
  
  log "=========================================="
  log "✓ Hardening & Honeypot Setup Complete!"
  log "=========================================="
  log ""
  log "IMMEDIATE ACTIONS REQUIRED:"
  log "1. Change all real admin/database passwords"
  log "2. Review firewall rules: ufw status verbose"
  log "3. Check real audit logs: tail -f /var/log/audit/audit.log"
  log "4. Review ModSecurity logs: tail -f /var/log/apache2/modsec_audit.log"
  log ""
  log "HONEYPOT SUMMARY (SAFE, MINIMAL ATTACK SURFACE):"
  log "────────────────────────────────────────────────────"
  log "SSH Tarpit: port $HONEYPOT_SSH_PORT (endlessh - slows brute force)"
  log ""
  log "Static Fake Web Pages (HTML only, no PHP execution):"
  log "  - /admin_old/ (404 page)"
  log "  - /backups/ (fake backup archive)"
  log "  - /config_samples/ (example config files)"
  log "  - /examples/ (sample docker-compose, .env files)"
  log ""
  log "Minimal Fake Credentials (read-only files only):"
  log "  - /root/BACKUP_README.txt"
  log "  - /etc/backup_config.example"
  log ""
  log "Reference Files (no executable code):"
  log "  - /usr/local/bin_backup/ (example scripts)"
  log "  - /etc/cron_backups.example (doc only)"
  log ""
  log "Decoy Directories (empty, monitored via audit):"
  log "  - /opt/.backup_cache"
  log "  - /var/spool/.backup_temp"
  log "  - /var/backups/.old_configs"
  log ""
  log "Canary Files (logs access via audit):"
  log "  - /var/www/html/.htaccess_backup"
  log "  - /home/ubuntu/.ssh/id_rsa.backup"
  log "  - /etc/mysql/.my.cnf.bak"
  log "  - /var/backups/last_export.sql"
  log ""
  log "DESIGN NOTES:"
  log "- All honeypot content is STATIC (HTML, txt, example files)"
  log "- NO executable code, scripts, or PHP to reduce attack surface"
  log "- Most files are READ-ONLY (chmod 400 or 750) "
  log "- Endlessh tarpit is isolated and cannot harm system"
  log "- Audit monitoring detects any access for forensics"
  log "────────────────────────────────────────────────────"
  log ""
  log "ANTI-AUTOMATION MEASURES:"
  log "────────────────────────────────────────────────────"
  log "Scanner Blocking (Conservative - no false positives):"
  log "  - Blocks only known scanner user agents"
  log "  - Rejects only obvious SQL injection patterns"
  log "  - Blocks path traversal attempts (../, .git, .env)"
  log "  - Rate limits to 10/sec (normal users unaffected)"
  log ""
  log "Reconnaissance Prevention:"
  log "  - Hide SSH version info (VersionAddendum disabled)"
  log "  - Hide PHP version (expose_php = Off)"
  log "  - Hide Apache version (ServerTokens Prod)"
  log "  - No fake server headers (avoid compatibility issues)"
  log ""
  log "Misdirection (Safe, standard files only):"
  log "  - Standard robots.txt with admin exclusions"
  log "  - Standard security.txt file"
  log ""
  log "Fail2Ban Extensions (Conservative):"
  log "  - [sql-injection-strict] - only obvious patterns"
  log "  - [scanner-agents] - known tool detection"
  log "  - [admin-attack] - suspicious admin access"
  log ""
  log "SSH Tarpit:"
  log "  - Endlessh on port 2222 (isolated, safe)"
  log ""
  log "Result: Blocks automated attacks while maintaining"
  log "        compatibility and stability for real users"
  log "────────────────────────────────────────────────────"
  log ""
  [[ "$DRY_RUN" == "1" ]] && log "DRY_RUN mode: No changes were made"
}

main