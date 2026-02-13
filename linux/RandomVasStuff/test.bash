#!/usr/bin/env bash
# Allow POP3(110/995), SMTP(25/465/587) and DNS(53 tcp/udp) via iptables and try to persist
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

PORTS_TCP=(110 995 25 465 587)
DNS_PORT=53

add_rule() {
  proto="$1"; dport="$2"
  if iptables -C INPUT -p "$proto" --dport "$dport" -j ACCEPT 2>/dev/null; then
    return
  fi
  iptables -I INPUT -p "$proto" --dport "$dport" -j ACCEPT
}

# Accept established/related
if ! iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
  iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fi

for p in "${PORTS_TCP[@]}"; do
  add_rule tcp "$p"
done

add_rule tcp "$DNS_PORT"
add_rule udp "$DNS_PORT"

# Persist rules
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
elif command -v iptables-save >/dev/null 2>&1; then
  if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
  elif [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables
  else
    iptables-save > /etc/iptables.rules || true
  fi
else
  echo "Warning: could not persist iptables rules automatically."
fi

echo "iptables rules applied."
```// filepath: scripts/allow_mail_dns_iptables.sh
#!/usr/bin/env bash
# Allow POP3(110/995), SMTP(25/465/587) and DNS(53 tcp/udp) via iptables and try to persist
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

PORTS_TCP=(110 995 25 465 587)
DNS_PORT=53

add_rule() {
  proto="$1"; dport="$2"
  if iptables -C INPUT -p "$proto" --dport "$dport" -j ACCEPT 2>/dev/null; then
    return
  fi
  iptables -I INPUT -p "$proto" --dport "$dport" -j ACCEPT
}

# Accept established/related
if ! iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
  iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fi

for p in "${PORTS_TCP[@]}"; do
  add_rule tcp "$p"
done

add_rule tcp "$DNS_PORT"
add_rule udp "$DNS_PORT"

# Persist rules
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save
elif command -v iptables-save >/dev/null 2>&1; then
  if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
  elif [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables
  else
    iptables-save > /etc/iptables.rules || true
  fi
else
  echo "Warning: could not persist iptables rules automatically."
fi

echo "iptables rules applied."