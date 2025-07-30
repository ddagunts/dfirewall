#!/bin/bash

# dfirewall IP-specific validation script example
# This script validates IP addresses and returns 0 (allow) or 1 (block)

IP="$1"
TYPE="$2"

if [ -z "$IP" ]; then
    echo "ERROR: No IP provided" >&2
    exit 1
fi

echo "Validating IP: $IP"

# Example IP-specific validation logic

# Block specific malicious IPs (you could load this from a file)
BLOCKED_IPS="192.0.2.1 198.51.100.100 203.0.113.1"
for blocked in $BLOCKED_IPS; do
    if [ "$IP" = "$blocked" ]; then
        echo "BLOCK: IP is in blocked list"
        exit 1
    fi
done

# Block IP ranges (example for certain ASNs or regions)
# Block example cloud provider ranges that shouldn't be accessed
if echo "$IP" | grep -q -E "^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"; then
    echo "BLOCK: IP in blocked range"
    exit 1
fi

# Block non-routable IPs that shouldn't appear in external DNS
if echo "$IP" | grep -q -E "^(0\.|127\.|169\.254\.|224\.|240\.)"; then
    echo "BLOCK: Non-routable IP"
    exit 1
fi

# Example: Block IPs with suspicious patterns
# IPs ending in .0 or .255 (network/broadcast addresses)
if echo "$IP" | grep -q -E "\.(0|255)$"; then
    echo "BLOCK: Network or broadcast address"
    exit 1
fi

# Example: Time-based blocking (block certain IPs during business hours)
HOUR=$(date +%H)
if [ "$HOUR" -ge 9 ] && [ "$HOUR" -le 17 ]; then
    # During business hours, block access to certain IPs
    if echo "$IP" | grep -q -E "^(1\.2\.3\.|4\.5\.6\.)"; then
        echo "BLOCK: IP blocked during business hours"
        exit 1
    fi
fi

echo "ALLOW: IP validation passed"
exit 0