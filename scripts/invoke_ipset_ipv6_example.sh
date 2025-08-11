#!/bin/sh

# This might work well if you are running "dfirewall" directly on the
# router and the router is a Linux machine with iptables and ipset.
# Due to ipset timeout capability this is likely the simplest option.
# Create an "ipset" for each local client with a list of allowed IPs.
# Default timeout is 60 but we have an explicit TTL set for every IP added

# Handle IPv4 and IPv6 addresses based on RECORD_TYPE
if [ "$RECORD_TYPE" = "A" ]; then
    # IPv4 handling
    ipset -N $CLIENT_IP --exist nethash timeout 60
    ipset --exist add $CLIENT_IP $RESOLVED_IP timeout $TTL
    
    mkdir /dev/shm/$CLIENT_IP || exit 0
    
    # add iptables rules for new ipset/client
    iptables -C FORWARD -s $CLIENT_IP -j REJECT || iptables -I FORWARD -s $CLIENT_IP -j REJECT
    iptables -C FORWARD -s $CLIENT_IP -j ACCEPT -m set --match-set $CLIENT_IP dst || \
    iptables -I FORWARD -s $CLIENT_IP -j ACCEPT -m set --match-set $CLIENT_IP dst
    
elif [ "$RECORD_TYPE" = "AAAA" ]; then
    # IPv6 handling
    ipset -N ${CLIENT_IP}_v6 --exist hash:net,net timeout 60 family inet6
    ipset --exist add ${CLIENT_IP}_v6 $RESOLVED_IP timeout $TTL
    
    mkdir /dev/shm/$CLIENT_IP || exit 0
    
    # add ip6tables rules for new ipset/client
    ip6tables -C FORWARD -s $CLIENT_IP -j REJECT || ip6tables -I FORWARD -s $CLIENT_IP -j REJECT
    ip6tables -C FORWARD -s $CLIENT_IP -j ACCEPT -m set --match-set ${CLIENT_IP}_v6 dst || \
    ip6tables -I FORWARD -s $CLIENT_IP -j ACCEPT -m set --match-set ${CLIENT_IP}_v6 dst
fi

# You might want to add a default FORWARD REJECT rule (and remove individual REJECT rules.. or not)
# If you are using ipset it makes sense to enable INVOKE_ALWAYS option