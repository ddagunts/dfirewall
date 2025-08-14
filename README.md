# dfirewall

DNS firewall, or dynamic firewall.

`note: this is very experimental, don't use anywhere resembling production`

The intent of this software is to (relatively) painlessly assist in implementing a "default deny" egress network policy at the edge with minimal impact to legitimate clients.

This is a DNS proxy intended to be placed in front of your DNS resolvers/forwarders (Pi-hole, etc). It monitors DNS requests and responses (IP addresses and TTLs) through Redis storage and script execution.

## Key Features
- **Default deny egress policy** - Block outgoing connections by default
- **DNS-driven firewall rules** - Force clients to perform DNS lookups through the server to gain access
- **Domain filtering** - Per-client blacklists and whitelists with network-based configuration
- **Time-limited access** - Allow clients outbound access to resolved IPs with automatic expiration based on TTL
- **Web UI dashboard** - View and monitor firewall rules through a web interface (port 8080)
- **IPv6 support** - Optional IPv6 DNS resolution and firewall rules
- **Redis integration** - Persistent storage of rules and client states
- **Script execution** - Execute custom scripts when new IP addresses are resolved
- **TLS SNI verification** - Transparent TCP proxy with SNI header verification for enhanced security

# Configuration
Configuration is handled through environmental variables. The following variables are available (variables which are unset are OPTIONAL):

```
PORT=53                      # DNS listening port (default: 53)
WEB_PORT=8080               # Web UI port (default: 8080)
UPSTREAM=8.8.8.8:53         # upstream DNS resolver host and port (REQUIRED)
REDIS=redis://127.0.0.1:6379 # location of Redis (REQUIRED)
INVOKE_SCRIPT=              # path of an executable for "dfirewall" to exec when it encounters a new IP address
ENABLE_EDNS=                # set to any value to enable adding requesting client IP to EDNS record (broken at this time)
ENABLE_IPV6=                # set to any value to enable IPv6 support
DEBUG=                      # set to any value to enable verbose logging
INVOKE_ALWAYS=              # set to any value to enable executing INVOKE_SCRIPT every time an IP address is encountered, even if already present in Redis
DOMAIN_WHITELIST_MODE=      # set to any value to enable whitelist mode (blocks all domains by default)
ENABLE_SNI_VERIFICATION=           # set to any value to enable TLS SNI verification proxy globally (legacy)
ENABLE_SNI_VERIFICATION_DEFAULT=   # set to any value to enable SNI verification by default for all clients
SNI_PROXY_IP=1.2.3.4               # IP address to use for SNI proxy substitution (default: 1.2.3.4)
SNI_PROXY_PORTS=443,8443           # comma-separated list of ports for SNI proxy to listen on (default: 443)
```

## TTL Padding Configuration

TTL padding extends firewall rule expiration beyond DNS record TTL, providing additional time for clients to access resolved IP addresses.

```
TTL_PAD_SECONDS_DEFAULT=60                 # Default padding for all clients (default: 30)
TTL_PAD_SECONDS_192_168_1_0_24=120         # IPv4: 192.168.1.0/24 gets 120 seconds
TTL_PAD_SECONDS_2001_db8_1__64=240         # IPv6: 2001:db8:1::/64 gets 240 seconds
```

## Domain Blacklist Configuration

Domain blacklists block DNS resolution for specified domains on a per-client network basis. Blocked domains return NXDOMAIN responses.

```
DOMAIN_BLACKLIST_DEFAULT=malware.com,ads.example.com     # Default blacklist for all clients
DOMAIN_BLACKLIST_192_168_1_0_24=social.com,gaming.net   # IPv4: 192.168.1.0/24 blocks these domains
DOMAIN_BLACKLIST_2001_db8_1__64=streaming.tv,news.org   # IPv6: 2001:db8:1::/64 blocks these domains
```

Features:
- Supports exact domain matching (e.g., `example.com`)
- Supports subdomain blocking (blocking `example.com` also blocks `sub.example.com`)
- Per-client network configuration using the same CIDR format as TTL padding
- Comma-separated domain lists
- Case-insensitive matching

## Domain Whitelist Configuration

Domain whitelists implement a "default deny" policy where ALL domains are blocked by default, allowing only explicitly whitelisted domains. This provides maximum security by blocking everything except approved domains.

```
DOMAIN_WHITELIST_MODE=1                                    # Enable whitelist mode (blocks all domains by default)
DOMAIN_WHITELIST_DEFAULT=google.com,github.com             # Default whitelist for all clients
DOMAIN_WHITELIST_192_168_1_0_24=work.com,company.net      # IPv4: 192.168.1.0/24 allows these domains
DOMAIN_WHITELIST_2001_db8_1__64=safe.org,trusted.edu      # IPv6: 2001:db8:1::/64 allows these domains
```

Features:
- **Default deny policy** - All domains blocked unless explicitly whitelisted
- **Per-client network configuration** - Different whitelists for different client IP ranges
- **Exact and subdomain matching** - Whitelisting `example.com` also allows `sub.example.com`
- **NXDOMAIN responses** - Non-whitelisted domains return proper DNS error responses
- **Case-insensitive matching** - Works regardless of domain case
- **Comma-separated lists** - Multiple domains per whitelist entry
- **Optional mode** - Whitelist only active when `DOMAIN_WHITELIST_MODE` is set

**Note:** Whitelist mode provides stronger security than blacklist mode. When enabled, it blocks ALL domains by default and only allows explicitly approved domains through.

## Per-Client SNI Verification Configuration

SNI verification can be enabled or disabled on a per-client network basis, similar to TTL padding and domain filtering.

```
ENABLE_SNI_VERIFICATION_DEFAULT=1                    # Default SNI verification for all clients
ENABLE_SNI_VERIFICATION_192_168_1_0_24=1             # IPv4: 192.168.1.0/24 has SNI verification enabled
ENABLE_SNI_VERIFICATION_192_168_2_0_24=0             # IPv4: 192.168.2.0/24 has SNI verification disabled
ENABLE_SNI_VERIFICATION_2001_db8_1__64=1             # IPv6: 2001:db8:1::/64 has SNI verification enabled
```

Features:
- Supports per-client network configuration using CIDR format
- IPv4 format: `ENABLE_SNI_VERIFICATION_192_168_1_0_24` → 192.168.1.0/24
- IPv6 format: `ENABLE_SNI_VERIFICATION_2001_db8_1__64` → 2001:db8:1::/64
- Default behavior controlled by `ENABLE_SNI_VERIFICATION_DEFAULT`
- Values: any non-empty value (except "0", "false") enables SNI verification
- Per-network settings override the default setting

## TLS SNI Verification

TLS SNI (Server Name Indication) verification provides an additional layer of security by intercepting TLS connections and verifying that the SNI header matches the originally requested domain.

```
# Global settings (affects all clients with SNI verification enabled)
SNI_PROXY_IP=1.2.3.4                        # IP address returned to clients for SNI-verified domains
SNI_PROXY_PORTS=443,8443,993,995            # Comma-separated list of ports for the SNI proxy to listen on

# Per-client configuration (see Per-Client SNI Verification Configuration above)
ENABLE_SNI_VERIFICATION_DEFAULT=1            # Enable SNI verification by default
ENABLE_SNI_VERIFICATION_192_168_1_0_24=1     # Enable for 192.168.1.0/24 network
ENABLE_SNI_VERIFICATION_192_168_2_0_24=0     # Disable for 192.168.2.0/24 network
```

### How it works:

1. **Per-Client Check**: For each DNS request, the system checks if SNI verification is enabled for the requesting client's IP
2. **DNS Response Modification**: When enabled for a client, DNS responses for A records are modified to return the configured `SNI_PROXY_IP` instead of the real IP address
3. **Connection Interception**: The TLS proxy listens on `SNI_PROXY_IP` for all configured ports and intercepts client connections
4. **SNI Extraction**: The proxy extracts the SNI header from the TLS ClientHello handshake
5. **Domain Verification**: The SNI is compared against the originally requested domain stored in Redis
6. **Traffic Forwarding**: If SNI matches, traffic is transparently forwarded to the real destination IP on the same port
7. **Connection Blocking**: If SNI doesn't match or is missing, the connection is dropped

### Benefits:

- **Enhanced Security**: Prevents clients from bypassing DNS-based filtering by connecting directly to IP addresses
- **Domain Enforcement**: Ensures clients can only access services using their legitimate domain names
- **TLS Interception Detection**: Blocks connections where SNI has been stripped or modified
- **Transparent Operation**: No configuration changes required on client devices
- **Per-Client Control**: Fine-grained control over which client networks have SNI verification enabled

### Example:

1. Client (192.168.1.100) requests DNS for `www.google.com` → resolves to `142.250.191.4`
2. System checks if SNI verification is enabled for 192.168.1.0/24 network
3. If enabled, DNS response returns `1.2.3.4` instead of the real IP
4. Client connects to `1.2.3.4:443` for HTTPS
5. TLS proxy extracts SNI from ClientHello, verifies it matches `www.google.com`
6. If valid, proxy forwards connection to real IP `142.250.191.4:443` (same port as intercepted)
7. Client and server communicate normally through the transparent proxy

If SNI verification is disabled for that client network, the client receives the real IP (142.250.191.4) and connects directly.
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

2) Enable IP forwarding and disable IPv6 (for now, IPv6 support is ToDo)
```
# echo "net.ipv4.ip_forward=1"                >  /etc/sysctl.d/router.conf
# echo "net.ipv6.conf.all.disable_ipv6=1"     >  /etc/sysctl.d/ipv6_disable.conf
# echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/ipv6_disable.conf
# sysctl --system
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

The Web UI will be available at http://localhost:8080 to view and monitor firewall rules.

# Testing
Connect a **new** client to the LAN, (or otherwise ensure clean DNS cache on the client), open some app to generate network traffic.  You should see some logs from dfirewall container.
```
root@debian:~/dfirewall# docker-compose logs --tail 5 dfirewall
Attaching to dfirewall
dfirewall    | 2025/07/30 03:01:37 Add 3.33.252.61 for 192.168.21.180, e16.whatsapp.net. 9m22s
dfirewall    | 2025/07/30 03:01:38 Add 157.240.229.60 for 192.168.21.180, graph.whatsapp.com. 53s
dfirewall    | 2025/07/30 03:01:38 Add 31.13.66.56 for 192.168.21.180, mmg.whatsapp.net. 59s
dfirewall    | 2025/07/30 03:15:06 Add 76.223.92.165 for 192.168.21.180, chat.signal.org. 4m11s
dfirewall    | 2025/07/30 03:15:07 Add 172.253.122.121 for 192.168.21.180, storage.signal.org. 31s
```
You should see clients, IPs resolved, and domains looked up in Redis
```
root@debian:~/dfirewall# docker exec -it redis redis-cli keys '*'
1) "rules:192.168.21.180:76.223.92.165:chat.signal.org."
2) "rules:192.168.21.180:172.253.122.121:storage.signal.org."
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
Finally, you should see two rules in iptables for every client on your LAN
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
Install some additional tools useful in network troubleshooting

`# apt -y install net-tools dnsutils netcat-openbsd lsof htop iftop --no-install-recommends`

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
As configured above, the firewall doesn't reject traffic from a client **until** at least one DNS request is made by the client.

# Current Status

## Implemented Features
- ✅ Basic DNS proxy with Redis integration
- ✅ Web UI dashboard for viewing firewall rules
- ✅ IPv6 support (DNS and firewall rules)
- ✅ Docker containerization with health checks
- ✅ Configurable web interface port
- ✅ Time-based rule expiration based on DNS TTL
- ✅ Script execution on new IP resolution

## ToDo
- fix EDNS handling
- add support for handling all IPs in a response (rather than selecting first IP only)  
- add Redis key expiration triggering or a watchdog (to enable non-Linux / non-ipset support)
- ~~add UI for viewing rules~~ ✅ **COMPLETED**
- add better configuration options (invoke custom script(s) per client (if exist), etc)
- ~~add support for checking IP and/or domain against blacklist in Redis (or file)~~ ✅ **COMPLETED** - Domain blacklist via environment variables
- add support for checking IP and/or domain against common reputation checkers
- add support for checking IP and/or domain by executing user-provided pass/fail script
- add API endpoints for rule management
- AI integration :D

## Recent Updates
- Added per-client domain whitelist functionality with "default deny" security model
- Added per-client domain blacklist functionality with environment variable configuration
- Added comprehensive Web UI with client and rule viewing
- Implemented IPv6 DNS resolution support
- Enhanced Redis key structure with record type tracking
- Improved Docker health checks and service dependencies
