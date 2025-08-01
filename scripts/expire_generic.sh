#!/bin/bash

# Generic expire script for non-Linux/non-ipset platforms
# This script is called when Redis keys expire, allowing cleanup of firewall rules
# Environment variables provided by dfirewall:
#   DFIREWALL_CLIENT_IP    - The client IP that requested the DNS resolution
#   DFIREWALL_RESOLVED_IP  - The IP address that was resolved
#   DFIREWALL_DOMAIN       - The domain name that was resolved
#   DFIREWALL_TTL          - Always "0" for expired keys
#   DFIREWALL_ACTION       - Always "EXPIRE" for expiration events

# ASSUMPTION: Log all expiration events for debugging and monitoring
echo "$(date): Key expired - Client: $DFIREWALL_CLIENT_IP, Resolved: $DFIREWALL_RESOLVED_IP, Domain: $DFIREWALL_DOMAIN"

# Remove IP from relevant ipset
ipset del "$DFIREWALL_CLIENT_IP" "$DFIREWALL_RESOLVED_IP" -exist

# EXAMPLE: For platforms with different firewall systems
# Uncomment and modify the appropriate section below:

# Example for Windows with netsh
# if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
#     netsh advfirewall firewall delete rule name="dfirewall-$RESOLVED_IP" dir=out
#     echo "Removed Windows firewall rule for $RESOLVED_IP"
# fi

# Example for macOS with pfctl
# if [[ "$OSTYPE" == "darwin"* ]]; then
#     # Remove from pf table (requires custom pf configuration)
#     pfctl -t dfirewall_allowed -T delete $RESOLVED_IP 2>/dev/null
#     echo "Removed from pfctl table: $RESOLVED_IP"
# fi

# Example for FreeBSD with ipfw
# if [[ "$OSTYPE" == "freebsd"* ]]; then
#     # Find and delete ipfw rules containing this IP
#     ipfw list | grep $RESOLVED_IP | awk '{print $1}' | xargs -I {} ipfw delete {}
#     echo "Removed ipfw rules for $RESOLVED_IP"
# fi

# Example for custom API-based firewalls
# curl -X DELETE "http://firewall-api/rules/$RESOLVED_IP" \
#     -H "Authorization: Bearer $API_TOKEN" \
#     -H "Content-Type: application/json"

# Example for cloud provider APIs (AWS Security Groups, etc.)
# aws ec2 revoke-security-group-ingress \
#     --group-id $SECURITY_GROUP_ID \
#     --protocol tcp \
#     --port 443 \
#     --cidr $RESOLVED_IP/32

echo "Expire script completed for $DFIREWALL_RESOLVED_IP (client: $DFIREWALL_CLIENT_IP, domain: $DFIREWALL_DOMAIN)"
