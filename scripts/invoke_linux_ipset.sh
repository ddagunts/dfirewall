#!/bin/sh

# This might work well if you are running "dfirewall" directly on the
# router and the router is a Linux machine with iptables and ipset.
# Due to ipset timeout capability this is likely the simplest option.
# Create an "ipset" for each local client with a list of allowed IPs.
# Default timeout is 60 but we have an explicit TTL set for every IP added

ipset -N "$DFIREWALL_CLIENT_IP" --exist nethash timeout 60
ipset --exist add "$DFIREWALL_CLIENT_IP" "$DFIREWALL_RESOLVED_IP" timeout "$DFIREWALL_TTL"

mkdir "/dev/shm/$DFIREWALL_CLIENT_IP" || exit 0

# add iptables rules for new ipset/client - use quoted variables
iptables -C FORWARD -s "$DFIREWALL_CLIENT_IP" -j REJECT || iptables -I FORWARD -s "$DFIREWALL_CLIENT_IP" -j REJECT
iptables -C FORWARD -s "$DFIREWALL_CLIENT_IP" -j ACCEPT -m set --match-set "$DFIREWALL_CLIENT_IP" dst || \
iptables -I FORWARD -s "$DFIREWALL_CLIENT_IP" -j ACCEPT -m set --match-set "$DFIREWALL_CLIENT_IP" dst

# You might want to add a default FORWARD REJECT rule (and remove individual REJECT rules.. or not)
# If you are using ipset it makes sense to enable INVOKE_ALWAYS option
