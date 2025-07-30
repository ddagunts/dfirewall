# dfirewall

dns firewall, or dynamic firewall.

`note: this is very experimental, don't use anywhere resembling production`

The intent of this software is to (relatively) painlessly assist in implementing a "default deny" egress network policy at the edge with minimal impact to legitimate clients.

This is a DNS proxy intended to be placed in front of your DNS resolvers/forwarders (Pi-hole, etc).  It allows to keep track of network activity by monitoring DNS requests and responses ( IP addresses and TTLs ) through reliance on Redis and execution of scripts.
It allows to create an IP firewall with the following features:
 - Block outgoing connections by default
 - Force clients to perform their DNS lookups through our server (or stay blocked)
 - Allow clients outbound access to IPs resolved, with timed expiration of rules
 - Turns any DNS block into a firewall block

# Configuration
Configuration is handled through environmental variables.  The following variables are available (variables which are unset are OPTIONAL):
```
PORT=                        # listening port
UPSTREAM=8.8.8.8:53          # upstream DNS resolver host and port (REQUIRED)
REDIS=redis://127.0.0.1:6379 # location of Redis (REQUIRED)
INVOKE_SCRIPT=               # path of an executable for "dfirewall" to exec when it encounters a new IP address (global fallback)
EXPIRE_SCRIPT=               # path of an executable for "dfirewall" to exec when Redis keys expire (global fallback)
SCRIPT_CONFIG=               # path to JSON configuration file for per-client script settings (overrides global settings)
BLACKLIST_CONFIG=            # path to JSON configuration file for IP/domain blacklisting
REPUTATION_CONFIG=           # path to JSON configuration file for IP/domain reputation checking
WEB_UI_PORT=                 # port for web-based rule management interface (e.g., 8080)
ENABLE_EDNS=                 # set to any value to enable EDNS Client Subnet with requesting client IP (supports IPv4/IPv6)
DEBUG=                       # set to any value to enable verbose logging
INVOKE_ALWAYS=               # set to any value to enable executing INVOKE_SCRIPT every time an IP address is encountered (global fallback)
```
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

# Optionally disable IPv6 if not needed (dfirewall now supports IPv6 via AAAA records)  
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

## Redis Key Expiration Monitoring (for non-Linux/non-ipset support)

If you're running dfirewall on non-Linux platforms or want to use custom firewall management, you can enable Redis key expiration monitoring:

```bash
# Set the EXPIRE_SCRIPT environment variable
EXPIRE_SCRIPT=/path/to/your/expire_script.sh

# Example using the provided generic expire script
EXPIRE_SCRIPT=./scripts/expire_generic.sh
```

When enabled, dfirewall will:
1. Monitor Redis keyspace notifications for expired keys
2. Execute your expire script when DNS TTLs expire
3. Pass the same environment variables as INVOKE_SCRIPT, plus `ACTION=EXPIRE`

**Redis Configuration Note**: Redis keyspace notifications must be enabled. dfirewall attempts to enable this automatically, but if it fails, run:
```bash
redis-cli CONFIG SET notify-keyspace-events Ex
```

## Web UI for Rule Management

dfirewall includes a built-in web interface for viewing and managing firewall rules. Enable it by setting the `WEB_UI_PORT` environment variable:

```bash
# Enable web UI on port 8080
WEB_UI_PORT=8080
```

Once enabled, access the web interface at `http://localhost:8080` (or your server's IP). The web UI provides:

- **Real-time Statistics**: View total rules, active clients, unique domains, and IPs
- **Rule Listing**: See all active firewall rules with TTL and expiration times
- **Rule Management**: Delete individual rules manually
- **Auto-refresh**: Interface updates every 30 seconds automatically

**Security Note**: The web UI is intended for internal use only. It runs on HTTP and should not be exposed to untrusted networks.

## Per-Client Script Configuration

dfirewall supports advanced per-client script configuration via JSON configuration files. This allows different firewall policies and scripts for different client IP ranges or patterns.

### Configuration File Format

Create a JSON configuration file and set `SCRIPT_CONFIG=/path/to/config.json`:

```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/default_invoke.sh",
    "expire_script": "/scripts/default_expire.sh", 
    "invoke_always": false,
    "environment": {
      "DEFAULT_POLICY": "deny"
    }
  },
  "clients": [
    {
      "client_pattern": "192.168.1.0/24",
      "description": "Corporate network",
      "invoke_script": "/scripts/corporate_invoke.sh",
      "invoke_always": true,
      "environment": {
        "SECURITY_LEVEL": "high",
        "AUDIT_LOG": "/var/log/corporate.log"
      }
    },
    {
      "client_pattern": "10.0.0.1",
      "description": "Admin workstation",
      "invoke_script": "/scripts/admin_invoke.sh"
    },
    {
      "client_pattern": "^172\\.16\\.(1[0-9]|2[0-9])\\..*",
      "description": "Development subnet (regex)",
      "invoke_script": "/scripts/dev_invoke.sh"
    }
  ]
}
```

### Pattern Types Supported

1. **Single IP**: `192.168.1.100` - Exact IP match
2. **CIDR Notation**: `192.168.1.0/24` - Subnet range  
3. **Regex Pattern**: `^192\.168\.(1|2)\..*` - Advanced pattern matching

### Configuration Priority

1. Client-specific settings (first matching pattern wins)
2. Default settings from configuration file
3. Environment variables (global fallback)

### Additional Features

- **Per-client environment variables**: Set custom variables for each client pattern
- **Selective script execution**: Override `invoke_always` per client
- **Custom expiration scripts**: Different cleanup behavior per client type
- **Audit and logging**: Track which configuration is used for each client

### Example Use Cases

- **Corporate networks**: Strict auditing and high-security scripts
- **Guest networks**: Basic firewall rules with limited access
- **Admin workstations**: Bypass restrictions or enhanced monitoring
- **IoT devices**: Quarantine suspicious activity with custom scripts
- **Development subnets**: Allow external API access for testing

## IP and Domain Blacklisting

dfirewall supports comprehensive blacklisting of malicious IPs and domains using both Redis and file-based approaches for enhanced security.

### Configuration

Create a blacklist configuration file and set `BLACKLIST_CONFIG=/path/to/blacklist-config.json`:

```json
{
  "redis_ip_set": "dfirewall:blacklist:ips",
  "redis_domain_set": "dfirewall:blacklist:domains", 
  "ip_blacklist_file": "/config/blacklist-ips.txt",
  "domain_blacklist_file": "/config/blacklist-domains.txt",
  "block_on_match": true,
  "log_only": false,
  "refresh_interval": 300
}
```

### Blacklist Types

#### Redis-Based Blacklists
- **Dynamic**: Updated in real-time via Redis commands
- **Scalable**: Supports millions of entries with fast lookups
- **Distributed**: Can be shared across multiple dfirewall instances
- **Persistent**: Survives restarts with Redis persistence

#### File-Based Blacklists  
- **Static**: Loaded from text files on disk
- **Simple**: Easy to manage with standard text editors
- **Version Controlled**: Can be managed with git/svn
- **Portable**: Easy to backup and transfer

### Blacklist File Format

IP blacklist file (`blacklist-ips.txt`):
```
# Comments start with #
192.0.2.1
203.0.113.5
198.51.100.10
```

Domain blacklist file (`blacklist-domains.txt`):
```
# Comments start with #
evil-site.com
malicious-domain.net
phishing-example.org
```

### Behavior Options

- **`block_on_match: true`**: Block DNS resolution for blacklisted entries
- **`log_only: true`**: Only log matches without blocking (audit mode)
- **`refresh_interval`**: How often to reload file-based blacklists (seconds)

### Domain Blocking Features

- **Case-insensitive matching**: Domains converted to lowercase
- **Parent domain blocking**: Blocking `evil.com` also blocks `sub.evil.com`
- **Trailing dot handling**: Properly handles DNS trailing dots

### IP Blocking Features

- **IPv4 and IPv6 support**: Blocks both address types
- **Exact matching**: Precise IP address matching
- **Response filtering**: Removes blacklisted IPs from DNS responses

### Management Tools

Use the provided script to manage Redis blacklists:

```bash
# Add entries
./scripts/manage_blacklists.sh add-ip 192.0.2.1
./scripts/manage_blacklists.sh add-domain evil.com

# Load from files
./scripts/manage_blacklists.sh load-ips /path/to/ips.txt
./scripts/manage_blacklists.sh load-domains /path/to/domains.txt

# List entries
./scripts/manage_blacklists.sh list-ips
./scripts/manage_blacklists.sh list-domains

# Show statistics
./scripts/manage_blacklists.sh stats
```

### Integration with Threat Intelligence

- **Automated feeds**: Script integration with threat intel APIs
- **Commercial feeds**: Support for commercial blacklist providers
- **Custom sources**: Easy integration with internal security tools
- **Real-time updates**: Redis allows instant blacklist updates

### Use Cases

- **Malware blocking**: Block known C&C servers and malware domains
- **Phishing protection**: Block phishing domains and IP addresses
- **Corporate policy**: Block social media, gambling, or adult content
- **Compliance**: Meet regulatory requirements for content filtering
- **DDoS mitigation**: Block known attack sources proactively

## IP and Domain Reputation Checking

dfirewall integrates with leading threat intelligence providers to automatically check IP addresses and domains against reputation databases in real-time.

### Configuration

Create a reputation configuration file and set `REPUTATION_CONFIG=/path/to/reputation-config.json`:

```json
{
  "version": "1.0",
  "cache_ttl": 3600,
  "checkers": [
    {
      "name": "virustotal_ip",
      "type": "ip",
      "provider": "virustotal",
      "enabled": true,
      "api_key": "your_virustotal_api_key_here",
      "base_url": "https://www.virustotal.com/api/v3",
      "timeout": 10,
      "rate_limit": 4,
      "cache_ttl": 7200,
      "threshold": 5.0,
      "headers": {
        "x-apikey": "your_virustotal_api_key_here"
      },
      "query_format": "/ip_addresses/{target}"
    }
  ]
}
```

### Supported Providers

#### VirusTotal
- **IP Reputation**: Checks IPs against VirusTotal's threat intelligence database
- **Domain Reputation**: Analyzes domains for malicious content and associations
- **API Key Required**: Get your free API key at [VirusTotal](https://www.virustotal.com/gui/join-us)
- **Rate Limits**: 4 requests/minute for free accounts, 1000/minute for premium

#### AbuseIPDB
- **IP Reputation**: Community-driven IP abuse reporting database
- **Confidence Scoring**: Percentage-based confidence scores for IP threats
- **API Key Required**: Free registration at [AbuseIPDB](https://www.abuseipdb.com/api)
- **Rate Limits**: 1000 requests/day for free accounts

#### URLVoid
- **Domain Reputation**: Checks domains against multiple security engines
- **Multi-Engine Analysis**: Aggregates results from 30+ security vendors
- **API Key Required**: Paid service at [URLVoid](https://www.urlvoid.com/api/)
- **Rate Limits**: Varies by subscription plan

#### Custom Providers
- **Flexible Integration**: Support for any REST API-based threat intelligence service
- **Custom Headers**: Authentication and custom request headers
- **Configurable Endpoints**: Adaptable URL patterns and query formats

### Reputation Checking Flow

1. **Domain Checking**: Before DNS resolution, domains are checked against reputation services
2. **IP Checking**: After DNS resolution, resolved IPs are checked for reputation
3. **Threshold-Based Blocking**: Configurable thresholds determine when to block
4. **Caching**: Results are cached to reduce API calls and improve performance
5. **Rate Limiting**: Built-in rate limiting respects provider API limits

### Configuration Options

#### Per-Checker Settings
- **`enabled`**: Enable/disable individual reputation checkers
- **`threshold`**: Minimum score to consider malicious (provider-specific)
- **`timeout`**: HTTP request timeout in seconds
- **`rate_limit`**: Maximum requests per minute to the provider
- **`cache_ttl`**: How long to cache reputation results (seconds)

#### Provider-Specific Settings
- **`api_key`**: Authentication key for the reputation service
- **`base_url`**: Base URL for the reputation API
- **`headers`**: Custom HTTP headers for authentication
- **`query_format`**: URL pattern with `{target}` placeholder for IP/domain

### Reputation Results

Each reputation check returns:
- **Score**: Numerical reputation score (interpretation varies by provider)
- **IsMalicious**: Boolean indicating if the target exceeds the threshold
- **Provider**: Which reputation service provided the result
- **Cached**: Whether the result came from cache or a fresh API call

### Blocking Behavior

- **Domain Blocking**: Malicious domains receive NXDOMAIN responses
- **IP Filtering**: Malicious IPs are removed from DNS responses
- **Logging**: All reputation actions are logged with scores and providers
- **Fallback**: Network errors don't block legitimate traffic

### Performance Features

#### Caching System
- **Redis-Based**: Uses existing Redis infrastructure for caching
- **TTL Management**: Configurable cache expiration per provider
- **Hash-Based Keys**: SHA-256 hashes prevent key collisions

#### Rate Limiting
- **Per-Provider Limits**: Individual rate limits for each reputation service
- **Token Bucket**: Prevents API quota exhaustion
- **Graceful Degradation**: Continues operation when rate limits are exceeded

#### Concurrent Processing
- **Async Checks**: Non-blocking reputation lookups
- **Timeout Protection**: Prevents slow APIs from blocking DNS responses
- **Error Handling**: Robust error handling for network issues

### Use Cases

#### Enterprise Security
- **APT Detection**: Block advanced persistent threat infrastructure
- **C&C Blocking**: Prevent communication with command & control servers
- **Data Exfiltration**: Block known data exfiltration domains
- **Compliance**: Meet regulatory requirements for threat intelligence

#### Network Monitoring
- **Threat Hunting**: Identify compromised devices contacting malicious IPs
- **Incident Response**: Track malware communications and IOCs
- **Forensics**: Log reputation data for security investigations

#### Automated Defense
- **Zero-Day Protection**: Block newly discovered threats automatically
- **IOC Integration**: Consume threat intelligence feeds in real-time
- **Dynamic Blocking**: Adapt to emerging threats without manual updates

### Integration Examples

#### Threat Intelligence Feeds
```bash
# Update VirusTotal API key
jq '.checkers[0].api_key = "new_api_key"' reputation-config.json > temp.json && mv temp.json reputation-config.json

# Enable AbuseIPDB checker
jq '.checkers[] | select(.provider == "abuseipdb") | .enabled = true' reputation-config.json
```

#### Custom Provider Integration
```json
{
  "name": "internal_threat_intel",
  "type": "ip",
  "provider": "custom",
  "enabled": true,
  "base_url": "https://internal-api.company.com",
  "timeout": 5,
  "rate_limit": 1000,
  "cache_ttl": 1800,
  "threshold": 8.0,
  "headers": {
    "Authorization": "Bearer internal_token",
    "X-Source": "dfirewall"
  },
  "query_format": "/threat-intel/check/{target}"
}
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

# ToDo
- ~~fix EDNS handling~~ ✅ **Completed** - Fixed EDNS Client Subnet with IPv4/IPv6 support and proper validation
- ~~add support for handling all IPs in a response (rather than selecting first IP only)~~ ✅ **Completed** - Added `HANDLE_ALL_IPS` environment variable option
- ~~add AAAA records (IPv6 support)~~ ✅ **Completed** - Added AAAA record processing for IPv6 addresses
- ~~add Redis key expiration triggering or a watchdog (to enable non-Linux / non-ipset support)~~ ✅ **Completed** - Added `EXPIRE_SCRIPT` with Redis keyspace notifications monitoring
- ~~add UI for viewing rules~~ ✅ **Completed** - Added web-based UI with rule viewing, statistics, and management features
- ~~add better configuration options (invoke custom script(s) per client (if exist), etc)~~ ✅ **Completed** - Added JSON-based per-client script configuration with pattern matching
- ~~add support for checking IP and/or domain against blacklist in Redis (or file)~~ ✅ **Completed** - Added comprehensive Redis and file-based IP/domain blacklisting
- ~~add support for checking IP and/or domain against common reputation checkers~~ ✅ **Completed** - Added integration with VirusTotal, AbuseIPDB, URLVoid, and custom reputation services
- add support for checking IP and/or domain by executing user-provided pass/fail script
- AI integration :D
