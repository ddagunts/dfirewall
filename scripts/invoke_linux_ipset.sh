#!/bin/sh

# This might work well if you are running "dfirewall" directly on the
# router and the router is a Linux machine with iptables and ipset.
# Due to ipset timeout capability this is likely the simplest option.
# Create an "ipset" for each local client with a list of allowed IPs.
# Default timeout is 60 but we have an explicit TTL set for every IP added

# Input validation - ensure variables are set and contain only safe characters
if [ -z "$CLIENT_IP" ] || [ -z "$RESOLVED_IP" ] || [ -z "$TTL" ]; then
    echo "Error: Required environment variables not set"
    exit 1
fi

# Validate IP address format (basic validation)
if ! echo "$CLIENT_IP" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null; then
    echo "Error: Invalid CLIENT_IP format"
    exit 1
fi

if ! echo "$RESOLVED_IP" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > /dev/null; then
    echo "Error: Invalid RESOLVED_IP format"
    exit 1
fi

# Validate TTL is numeric
if ! echo "$TTL" | grep -E '^[0-9]+(\.[0-9]+)?$' > /dev/null; then
    echo "Error: Invalid TTL format"
    exit 1
fi

# Use quoted variables to prevent shell injection
ipset -N "$CLIENT_IP" --exist nethash timeout 60
ipset --exist add "$CLIENT_IP" "$RESOLVED_IP" timeout "$TTL"

mkdir "/dev/shm/$CLIENT_IP" || exit 0

# add iptables rules for new ipset/client - use quoted variables
iptables -C FORWARD -s "$CLIENT_IP" -j REJECT || iptables -I FORWARD -s "$CLIENT_IP" -j REJECT
iptables -C FORWARD -s "$CLIENT_IP" -j ACCEPT -m set --match-set "$CLIENT_IP" dst || \
iptables -I FORWARD -s "$CLIENT_IP" -j ACCEPT -m set --match-set "$CLIENT_IP" dst

# You might want to add a default FORWARD REJECT rule (and remove individual REJECT rules.. or not)
# If you are using ipset it makes sense to enable INVOKE_ALWAYS option
