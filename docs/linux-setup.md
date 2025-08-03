# Setup on Linux

Start with a minimal Debian install

The example instructions assume that the machine:
- has two network interfaces
- WAN has a DHCP server willing to give you an IPv4 address
- LAN is using 192.168.21.0/24 subnet
- 1.1.1.1:53 is accessible
- WAN interface name is "enp2s0f0.3"
- LAN interface name is "ens9.31"

You will need to account at least for the interface names

1) Configure the network interfaces

Use `/etc/network/interfaces` to configure your NICs, here is my example:
```
auto lo
iface lo inet loopback

auto enp2s0f0.3
iface enp2s0f0.3 inet dhcp

auto ens9.31
iface ens9.31 inet static
  address 192.168.21.1/24
  netmask 255.255.255.0
```
```
# /etc/init.d/networking restart
Restarting networking (via systemctl): networking.service.
```

2) Enable IP forwarding and optionally disable IPv6 (IPv6 is now supported via AAAA records)
```
# Enable IP forwarding (required)
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/router.conf

# Optionally disable IPv6 if not needed (dfirewall supports IPv6 addresses and AAAA records)  
# echo "net.ipv6.conf.all.disable_ipv6=1"     >  /etc/sysctl.d/ipv6_disable.conf
# echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/ipv6_disable.conf

# Apply changes
sysctl --system
```
```
# ip ad sh enp2s0f0.3
4: enp2s0f0.3@enp2s0f0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether c8:2a:14:0f:7c:9f brd ff:ff:ff:ff:ff:ff
    inet 192.168.3.137/24 brd 192.168.3.255 scope global dynamic enp2s0f0.3
       valid_lft 446sec preferred_lft 446sec
# ip ad sh ens9.31
5: ens9.31@ens9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 38:c9:86:13:f2:23 brd ff:ff:ff:ff:ff:ff
    inet 192.168.21.1/24 brd 192.168.21.255 scope global ens9.31
       valid_lft forever preferred_lft forever
```
Install packages we need for a firewall (iptables, ipset, and git to clone this)
```
# DEBIAN_FRONTEND=noninteractive apt -y install iptables ipset dnsmasq iptables-persistent git
```

# Enable NAT (starting with empty iptables ruleset)

Create iptables-persistent rules and restore them (**replace the WAN interface name**)
```
cat > /etc/iptables/rules.v4 <<EOF
*nat
-A POSTROUTING -o enp2s0f0.3 -j MASQUERADE
COMMIT

*filter
-A INPUT -i lo -j ACCEPT
# allow established connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# drop on WAN otherwise
-A INPUT -i enp2s0f0.3 -j DROP
COMMIT
EOF

# iptables-restore < /etc/iptables/rules.v4
```
Ruleset after loading rules:
```
# iptables -L 
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
#  iptables -L -t nat
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination         
MASQUERADE  all  --  anywhere             anywhere           
```
# Start DHCP server 
(**replace LAN interface name with your interface**)
```
# setup dnsmasq as a DHCP server for the LAN
cat > /etc/dnsmasq.conf <<EOF
interface=ens9.31 # edit this
listen-address=127.0.0.1
port=0
domain=lan
dhcp-range=192.168.21.100,192.168.21.200,1h
dhcp-option=option:dns-server,192.168.21.1
EOF
```
```
#  systemctl enable dnsmasq.service && systemctl restart dnsmasq.service
```
Now your Debian machine should be a router

# Install Docker, clone this repo, and run dfirewall
```
# mkdir /etc/docker
# echo '{ "iptables": false }' > /etc/docker/daemon.json
# apt -y install docker.io docker-compose --no-install-recommends
# systemctl enable docker && systemctl start docker
# git clone https://github.com/ddagunts/dfirewall 
# cd dfirewall
# docker-compose up -d
```

# Testing
Connect a **new** client to the LAN, (or otherwise ensure clean DNS cache on the client), open some app to generate network traffic.  You should see some logs from dfirewall container.
```
root@debian:~/dfirewall# docker-compose logs -f dfirewall 
Attaching to dfirewall
dfirewall    | 2025/08/01 14:29:48 listening on port 53, set PORT env var to change
dfirewall    | 2025/08/01 14:29:48 INVOKE_SCRIPT is set to /scripts/invoke_linux_ipset.sh
dfirewall    | 2025/08/01 14:29:48 INVOKE_ALWAYS is set, executing INVOKE script for every matching request
dfirewall    | 2025/08/01 14:29:48 EXPIRE_SCRIPT is set to /scripts/expire_generic.sh
dfirewall    | 2025/08/01 14:29:48 WEB_UI_PORT is set to 8080
dfirewall    | 2025/08/01 14:29:48 SCRIPT_CONFIG env var not set, using environment variables for script configuration
dfirewall    | 2025/08/01 14:29:48 Loaded blacklist configuration: Redis IP key=dfirewall:blacklist:ips, Redis domain key=dfirewall:blacklist:domains, IP file=, domain file=
dfirewall    | 2025/08/01 14:29:48 BLACKLIST_CONFIG loaded from /config/blacklist-config.example.json
dfirewall    | 2025/08/01 14:29:48 REPUTATION_CONFIG env var not set, reputation checking disabled
dfirewall    | 2025/08/01 14:29:48 AI_CONFIG env var not set, AI features disabled
dfirewall    | 2025/08/01 14:29:48 CUSTOM_SCRIPT_CONFIG env var not set, custom script validation disabled
dfirewall    | 2025/08/01 14:29:48 Connected to Redis at 127.0.0.1:6379
dfirewall    | 2025/08/01 14:29:48 Redis connection succeeded
dfirewall    | 2025/08/01 14:29:48 Redis IP blacklist key 'dfirewall:blacklist:ips' ready for use (will be created on first addition)
dfirewall    | 2025/08/01 14:29:48 Redis domain blacklist key 'dfirewall:blacklist:domains' ready for use (will be created on first addition)
dfirewall    | 2025/08/01 14:29:48 Started blacklist refresh background task (interval: 30 seconds)
dfirewall    | 2025/08/01 14:29:48 Enabled Redis keyspace notifications for key expiration events
dfirewall    | 2025/08/01 14:29:48 dfirewall started
dfirewall    | 2025/08/01 14:29:48 Auth config loaded - HTTPS: false, Password: false, LDAP: false, Header: false
dfirewall    | 2025/08/01 14:29:48 Starting web UI server on port 8080 (HTTPS: false, Auth: false)
dfirewall    | 2025/08/01 14:29:48 Started Redis expiration watchdog, monitoring key expiration events
dfirewall    | 2025/08/01 14:29:48 EXPIRE_SCRIPT is set to: /scripts/expire_generic.sh
dfirewall    | 2025/08/01 14:30:36 Key expired: rules:192.168.21.141|104.16.185.241|icanhazip.com. (client=192.168.21.141, resolved=104.16.185.241, domain=icanhazip.com.)
dfirewall    | 2025/08/01 14:30:36 Key expired: rules:192.168.21.141|104.16.184.241|icanhazip.com. (client=192.168.21.141, resolved=104.16.184.241, domain=icanhazip.com.)
```
You should see clients, IPs resolved, and domains looked up in Redis
```
root@debian:~/dfirewall# docker exec -it redis redis-cli keys '*'
 1) "rules:192.168.21.142|185.199.109.133|raw.githubusercontent.com."
 2) "rules:192.168.21.141|96.7.128.186|example.org."
```
You should see ipsets on the host being populated by the container.  Note that the second Signal IP (172.253.122.121) had a low TTL of 31s and expired out of the list already
```
# ipset list
Name: 192.168.21.180
Type: hash:net 
Revision: 7  
Header: family inet hashsize 1024 maxelem 65536 timeout 60 bucketsize 12 initval 0x928f08a1
Size in memory: 5640
References: 1
Number of entries: 1
Members:
76.223.92.165 timeout 144
```
You should see two rules in iptables for every client on your LAN
```
# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
DROP       all  --  anywhere             anywhere            
 
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  192.168.21.180       anywhere             match-set 192.168.21.180 dst
REJECT     all  --  192.168.21.180       anywhere             reject-with icmp-port-unreachable
ACCEPT     all  --  192.168.21.158       anywhere             match-set 192.168.21.158 dst
REJECT     all  --  192.168.21.158       anywhere             reject-with icmp-port-unreachable

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```
You can also look at the web interface at http://192.168.21.1:8080
You can also manually delete rules from the web ui (TODO: add button to also add domain to blacklist in Redis)
<img width="1476" height="1268" alt="Screenshot from 2025-08-01 09-16-27" src="https://github.com/user-attachments/assets/2bd3206d-cc91-4bb6-b727-56ad53520b49" />


This example configuration has domain blacklisting via Redis enabled you can experiment with
```
root@debian:~/dfirewall# docker exec -it dfirewall /scripts/manage_blacklists.sh 
Usage: /scripts/manage_blacklists.sh <command> [arguments]

Commands:
  add-ip <ip>              Add IP to blacklist
  remove-ip <ip>           Remove IP from blacklist
  add-domain <domain>      Add domain to blacklist
  remove-domain <domain>   Remove domain from blacklist
  list-ips                 List all blacklisted IPs
  list-domains            List all blacklisted domains
  load-ips <file>         Load IPs from file to Redis
  load-domains <file>     Load domains from file to Redis
  clear-ips               Clear all IP blacklists
  clear-domains           Clear all domain blacklists
  stats                   Show blacklist statistics

Environment variables:
  REDIS_HOST              Redis host (default: 127.0.0.1)
  REDIS_PORT              Redis port (default: 6379)
  IP_SET                  Redis set name for IPs (default: dfirewall:blacklist:ips)
  DOMAIN_SET              Redis set name for domains (default: dfirewall:blacklist:domains)
root@debian:~/dfirewall# docker exec -it dfirewall /scripts/manage_blacklists.sh list-domains
Blacklisted domains:
1) "www.google.com"
root@debian:~/dfirewall# dig www.google.com @192.168.21.1

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> www.google.com @192.168.21.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 32097
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;www.google.com.			IN	A

;; Query time: 0 msec
;; SERVER: 192.168.21.1#53(192.168.21.1) (UDP)
;; WHEN: Wed Jul 30 22:14:29 EDT 2025
;; MSG SIZE  rcvd: 32
```

Install optional tools useful on a router

`apt -y install net-tools dnsutils netcat-openbsd tcpdump lsof htop iftop ldnsutils netdiscover --no-install-recommends`

# Test from a client on the LAN
Try to ping some IP (1.1.1.1), it should fail.  Then try to ping it by name (one.one.one.one).  Then try to ping it by IP again.  Ping by IP should work until the TTL in the ipset expires.
```
$ ping -c1 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
From 192.168.21.1 icmp_seq=1 Destination Port Unreachable

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms

$ ping -c1 one.one.one.one
PING one.one.one.one (1.1.1.1) 56(84) bytes of data.
64 bytes from one.one.one.one (1.1.1.1): icmp_seq=1 ttl=58 time=8.34 ms

--- one.one.one.one ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 8.342/8.342/8.342/0.000 ms

$ ping -c1 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=70.0 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 70.018/70.018/70.018/0.000 ms

```

# Notes about the example setup
Note that it would be better not to insert an individual REJECT rule for each client (remove `iptables -C FORWARD -s $CLIENT_IP -j REJECT || iptables -I FORWARD -s $CLIENT_IP -j REJECT` line from `scripts/invoke_linux_ipset.sh`) and instead reject forwarded traffic by default:
```
root@debian:~/dfirewall# cat /etc/iptables/rules.v4
*nat
-A POSTROUTING -o enp2s0f0.3 -j MASQUERADE
COMMIT

*filter                      
-A INPUT -i lo -j ACCEPT     
# allow established connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# drop on WAN otherwise      
-A INPUT -i enp2s0f0.3 -j DROP 
-A FORWARD -s 192.168.21.0/24 -j REJECT
COMMIT
```
As configured in this example, the firewall doesn't reject traffic from a client **until** at least one DNS request is made by the client.

Since the example setup uses ipset we don't need EXPIRE_SCRIPT enabled (since IPs expire on their own), but it does allow the "Delete" button in the UI to work.
