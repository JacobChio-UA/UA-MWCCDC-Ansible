#!/bin/bash

# Define the ports and protocols you want to allow

ALLOWED_PORTS=("25/tcp" "53/tcp" "110/tcp" "143/tcp" "587/tcp" "995/tcp")

# The location of the iptables program
IPTABLES=/sbin/iptables

echo "Configuring iptables to allow only specific ports..."

# 1. Flush all existing rules and delete all non-default chains
$IPTABLES -F
$IPTABLES -X
echo "Existing rules flushed."

# 2. Set the default INPUT and FORWARD policies to DROP
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
# The OUTPUT policy is generally left as ACCEPT to allow normal outbound traffic, 
# but can be restricted if needed.
$IPTABLES -P OUTPUT ACCEPT
echo "Default policies set to DROP for INPUT/FORWARD, ACCEPT for OUTPUT."

# 3. Allow all traffic on the loopback interface (localhost communication)
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT
echo "Loopback traffic allowed."

# 4. Allow established and related incoming connections 
# This is crucial for allowing responses to your outgoing connections.
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "Established and related connections allowed."

# 5. Explicitly allow the specific incoming ports defined above
for port_proto in "${ALLOWED_PORTS[@]}"; do
    PORT=$(echo $port_proto | cut -d'/' -f1)
    PROTO=$(echo $port_proto | cut -d'/' -f2)
    $IPTABLES -A INPUT -p $PROTO --dport $PORT -j ACCEPT
    echo "Allowed incoming port $PORT/$PROTO."
done

# 6. Save the rules (command varies by Linux distribution)
# For Debian/Ubuntu, you might need 'netfilter-persistent save' or 'iptables-save'
# For RHEL/CentOS, use 'service iptables save'.
# A general way to save is to use iptables-save command:
/sbin/iptables-save > /etc/sysconfig/iptables
echo "Iptables rules saved (check /etc/sysconfig/iptables file for verification/persistence)."

echo "Iptables configuration complete."