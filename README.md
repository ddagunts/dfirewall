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
Configuration is handled through environmental variables.  The following variables are available:
```
PORT=                        # listening port (OPTIONAL)
UPSTREAM=8.8.8.8:53          # upstream DNS resolver host and port (REQUIRED)
REDIS=redis://127.0.0.1:6379 # location of Redis (REQUIRED)
# Redis Security Configuration (OPTIONAL)
REDIS_PASSWORD=              # Redis authentication password (overrides URL password)
REDIS_TLS=true               # enable TLS/SSL connection to Redis (true/1/enabled)
REDIS_TLS_CERT=              # path to client certificate file for mutual TLS
REDIS_TLS_KEY=               # path to client private key file for mutual TLS
REDIS_TLS_CA=                # path to CA certificate file for server verification
REDIS_TLS_SERVER_NAME=       # override server name for TLS certificate verification
REDIS_TLS_SKIP_VERIFY=       # skip TLS certificate verification (NOT recommended for production)
# Redis Performance Configuration (OPTIONAL)
REDIS_MAX_RETRIES=3          # maximum connection retry attempts
REDIS_DIAL_TIMEOUT=5s        # connection establishment timeout
REDIS_READ_TIMEOUT=3s        # read operation timeout
REDIS_WRITE_TIMEOUT=3s       # write operation timeout
REDIS_POOL_SIZE=10           # connection pool size
INVOKE_SCRIPT=               # path of an executable for "dfirewall" to exec when it encounters a new IP address (global fallback) (OPTIONAL)
EXPIRE_SCRIPT=               # path of an executable for "dfirewall" to exec when Redis keys expire (global fallback) (OPTIONAL)
SCRIPT_CONFIG=               # path to JSON configuration file for per-client script settings (overrides global settings) (OPTIONAL)
BLACKLIST_CONFIG=            # path to JSON configuration file for IP/domain blacklisting  (OPTIONAL)
REPUTATION_CONFIG=           # path to JSON configuration file for IP/domain reputation checking  (OPTIONAL)
AI_CONFIG=                   # path to JSON configuration file for AI-powered threat detection  (OPTIONAL)
CUSTOM_SCRIPT_CONFIG=        # path to JSON configuration file for user-provided pass/fail scripts  (OPTIONAL)
WEB_UI_PORT=                 # port for web-based rule management interface (e.g., 8080) (OPTIONAL)
# Web UI Authentication Configuration (OPTIONAL)
WEBUI_AUTH_CONFIG=           # path to JSON configuration file for Web UI authentication settings
WEBUI_HTTPS_ENABLED=         # enable HTTPS (true/false)
WEBUI_CERT_FILE=             # path to TLS certificate file for HTTPS
WEBUI_KEY_FILE=              # path to TLS private key file for HTTPS
WEBUI_PASSWORD_AUTH=         # enable password authentication (true/false)
WEBUI_USERNAME=              # username for password authentication
WEBUI_PASSWORD=              # password for authentication (will be hashed automatically)
WEBUI_LDAP_AUTH=             # enable LDAP authentication (true/false)
WEBUI_LDAP_SERVER=           # LDAP server hostname
WEBUI_LDAP_PORT=             # LDAP server port (default: 389)
WEBUI_LDAP_BASE_DN=          # LDAP base DN for user search
WEBUI_LDAP_BIND_DN=          # LDAP bind DN for service account
WEBUI_LDAP_BIND_PASS=        # LDAP bind password for service account
WEBUI_LDAP_USER_ATTR=        # LDAP user attribute (default: uid)
WEBUI_LDAP_SEARCH_FILTER=    # LDAP search filter for users
WEBUI_HEADER_AUTH=           # enable header-based authentication (true/false)
WEBUI_HEADER_NAME=           # HTTP header name to check for authentication
WEBUI_HEADER_VALUES=         # comma-separated list of valid header values
WEBUI_TRUSTED_PROXIES=       # comma-separated list of trusted proxy IPs/CIDRs
WEBUI_SESSION_SECRET=        # secret key for session signing (auto-generated if not provided)
WEBUI_SESSION_EXPIRY=        # session expiry time in hours (default: 24)
ENABLE_EDNS=                 # set to any value to enable EDNS Client Subnet with requesting client IP (supports IPv4/IPv6) (OPTIONAL)
DEBUG=                       # set to any value to enable verbose logging (OPTIONAL)
INVOKE_ALWAYS=               # set to any value to enable executing INVOKE_SCRIPT every time an IP address is encountered (global fallback) (OPTIONAL)
HANDLE_ALL_IPS=              # set to any value to enable creating rules for all IPs in a response (OPTIONAL)
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

## Redis Security Configuration

dfirewall supports secure Redis connections with TLS encryption and authentication.

**Key Security Features:**
- Password authentication with secure connection URLs
- TLS/SSL encryption for data in transit  
- Mutual TLS (mTLS) with client certificates
- Connection pooling and performance tuning
- Production-ready deployment examples

**Quick Setup:**
```bash
# Basic authenticated connection
REDIS=redis://:password@127.0.0.1:6379
REDIS_PASSWORD=your_secure_password

# TLS encrypted connection
REDIS_TLS=true
REDIS=rediss://127.0.0.1:6380
```

**📖 For detailed configuration, see:** [docs/redis-security.md](docs/redis-security.md)

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
- **Blacklist Management**: Add/remove IPs and domains from blacklists
- **Reputation Checking**: Check IP/domain reputation with threat intelligence providers
- **AI Analysis**: Analyze domains and IPs for threats using AI providers
- **Auto-refresh**: Interface updates every 30 seconds automatically

### Web UI Authentication and Security
The Web UI supports enterprise-grade authentication and security features:

**Supported Authentication Methods:**
- **HTTPS/TLS encryption** with custom certificates
- **Password authentication** with bcrypt hashing
- **LDAP integration** for enterprise environments  
- **Header-based auth** for reverse proxy setups
- **Session management** with JWT tokens

**Quick Setup:**
```bash
# Enable HTTPS with password authentication
export WEBUI_HTTPS_ENABLED=true
export WEBUI_CERT_FILE=/path/to/certificate.crt
export WEBUI_KEY_FILE=/path/to/private.key
export WEBUI_PASSWORD_AUTH=true
export WEBUI_USERNAME=admin
export WEBUI_PASSWORD=your_secure_password

# Generate self-signed certificate
./scripts/generate-cert.sh localhost ./certs
```

**📖 For detailed authentication setup, see:** [docs/webui-authentication.md](docs/webui-authentication.md)

## Per-Client Script Configuration

dfirewall supports advanced per-client script configuration for different firewall policies based on client identity and network location.

**Key Features:**
- **Pattern Matching**: CIDR, single IP, and regex pattern support
- **Script Customization**: Different invoke/expire scripts per client
- **Environment Variables**: Custom variables for each client pattern
- **Priority System**: Client-specific → defaults → global fallback

**Quick Setup:**
```bash
export SCRIPT_CONFIG=/path/to/script-config.json
```

**Example Configuration:**
```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/default_invoke.sh",
    "environment": {"POLICY": "moderate"}
  },
  "clients": [
    {
      "client_pattern": "192.168.1.0/24",
      "description": "Corporate network",
      "invoke_script": "/scripts/corporate_strict.sh",
      "environment": {"SECURITY_LEVEL": "high"}
    }
  ]
}
```

**📖 For detailed configuration, see:** [docs/per-client-scripts.md](docs/per-client-scripts.md)

## IP and Domain Blacklisting

dfirewall supports comprehensive blacklisting of malicious IPs and domains using both Redis and file-based approaches.

**Key Features:**
- **Dynamic Redis Blacklists**: Real-time updates via Redis commands
- **Static File Blacklists**: Simple text file management
- **Pattern Matching**: Wildcard and regex pattern support
- **IPv4/IPv6 Support**: Complete IP address family coverage
- **Web UI Management**: Add/remove entries via web interface

**Quick Setup:**
```bash
export BLACKLIST_CONFIG=/path/to/blacklist-config.json
```

**Example Configuration:**
```json
{
  "enabled": true,
  "ip_blacklist": ["192.168.100.5", "10.0.0.0/8"],
  "domain_blacklist": ["malware.example.com", "*.phishing.com"],
  "use_redis_blacklist": true,
  "redis_ip_key": "dfirewall:blacklist:ips",
  "redis_domain_key": "dfirewall:blacklist:domains"
}
```

**📖 For detailed configuration, see:** [docs/blacklist-configuration.md](docs/blacklist-configuration.md)

## IP and Domain Reputation Checking

dfirewall integrates with leading threat intelligence providers for real-time security analysis.

**Supported Providers:**
- **VirusTotal**: Multi-engine threat intelligence analysis
- **AbuseIPDB**: Community-driven IP abuse reporting
- **URLVoid**: Multi-vendor domain reputation checking
- **Custom APIs**: Flexible integration with any REST-based threat intelligence

**Key Features:**
- Real-time reputation checking before DNS resolution
- Configurable threat score thresholds  
- Intelligent caching to reduce API costs
- Rate limiting to respect provider quotas
- Comprehensive logging and monitoring

**Quick Setup:**
```bash
export REPUTATION_CONFIG=/path/to/reputation-config.json
```

**📖 For detailed configuration, see:** [docs/ai-and-reputation.md](docs/ai-and-reputation.md)

## AI-Powered Threat Detection

dfirewall integrates cutting-edge AI technology for advanced threat detection and analysis.

**Supported AI Providers:**
- **OpenAI GPT Models**: Advanced reasoning and threat analysis
- **Anthropic Claude**: Security-focused analytical capabilities  
- **Local AI Models**: Privacy-first offline operation

**AI-Powered Features:**
- **Domain Analysis**: Intelligent malware and phishing detection
- **Traffic Anomaly Detection**: Behavioral analysis of DNS patterns
- **Proactive Threat Hunting**: Zero-day and APT identification
- **DGA Recognition**: Domain Generation Algorithm detection

**Quick Setup:**
```bash
export AI_CONFIG=/path/to/ai-config.json
```

**Example Configuration:**
```json
{
  "enabled": true,
  "provider": "openai",
  "api_key": "your_openai_api_key",
  "model": "gpt-4",
  "domain_analysis": true,
  "traffic_anomalies": true,
  "min_confidence": 0.8
}
```

**📖 For detailed configuration, see:** [docs/ai-and-reputation.md](docs/ai-and-reputation.md)
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

## AI-Powered Threat Detection :D

dfirewall integrates cutting-edge AI technology to provide advanced threat detection and analysis capabilities, going beyond traditional rule-based approaches to identify sophisticated attacks and anomalous behavior.

### Configuration

Create an AI configuration file and set `AI_CONFIG=/path/to/ai-config.json`:

```json
{
  "enabled": true,
  "provider": "openai",
  "api_key": "your_openai_api_key_here",
  "base_url": "https://api.openai.com/v1",
  "model": "gpt-4",
  "timeout": 30,
  
  "domain_analysis": true,
  "traffic_anomaly": true,
  "threat_hunting": true,
  "adaptive_blocking": false,
  
  "analysis_window": 10,
  "confidence_threshold": 0.7,
  "max_analysis_requests": 60
}
```

### AI Providers

#### OpenAI GPT Models
- **Provider**: `openai`
- **Models**: `gpt-4`, `gpt-3.5-turbo`
- **API Key**: Required from [OpenAI Platform](https://platform.openai.com/)
- **Strengths**: Excellent reasoning and threat analysis capabilities
- **Rate Limits**: Varies by account tier

#### Anthropic Claude
- **Provider**: `claude`
- **Models**: `claude-3-sonnet-20240229`, `claude-3-haiku-20240307`
- **API Key**: Required from [Anthropic Console](https://console.anthropic.com/)
- **Strengths**: Strong analytical capabilities and security-focused reasoning
- **Rate Limits**: Varies by account tier

#### Local AI Models
- **Provider**: `local`
- **Models**: `llama2`, `mistral`, `codellama`, custom models
- **Setup**: Requires local AI server (Ollama, LocalAI, etc.)
- **Strengths**: Privacy, no API costs, customizable
- **Considerations**: Requires significant computational resources

### AI-Powered Features

#### 1. Domain Analysis
**Purpose**: AI analyzes requested domains for potential threats before DNS resolution.

**Capabilities**:
- **Malware Detection**: Identifies domains hosting malware or used for malware distribution
- **Phishing Detection**: Recognizes phishing domains and typosquatting attempts
- **C&C Infrastructure**: Detects command & control server domains
- **DGA Recognition**: Identifies Domain Generation Algorithm patterns
- **Suspicious Patterns**: Analyzes naming patterns and registration characteristics

**Configuration**: `"domain_analysis": true`

**Example AI Analysis**:
```
Domain: xn--80abbmbccd7a0e.com
AI Assessment: MALICIOUS (Confidence: 0.85)
Reasoning: "Suspicious punycode domain with recent registration, 
resembles phishing patterns targeting banking sites. High entropy 
subdomain suggests automated generation."
Categories: ["phishing", "punycode_abuse", "typosquatting"]
```

#### 2. Traffic Anomaly Detection
**Purpose**: AI monitors DNS traffic patterns to identify anomalous behavior that may indicate compromise.

**Capabilities**:
- **Beaconing Detection**: Identifies regular communication patterns typical of malware
- **Data Exfiltration**: Detects unusual volume and diversity patterns
- **DGA Traffic**: Recognizes algorithmically generated domain requests
- **Temporal Anomalies**: Identifies unusual timing patterns in DNS requests
- **Volume Anomalies**: Detects sudden spikes or unusual request volumes

**Configuration**: `"traffic_anomaly": true`

**Detection Metrics**:
- Request rate analysis (requests per minute)
- Domain diversity scoring
- Temporal pattern analysis
- Burst detection
- Beaconing probability scoring

#### 3. Proactive Threat Hunting
**Purpose**: AI continuously analyzes network data to proactively identify potential threats.

**Capabilities**:
- **IOC Correlation**: Connects seemingly unrelated indicators
- **Campaign Detection**: Identifies coordinated attack campaigns
- **Zero-Day Recognition**: Detects novel attack patterns
- **Lateral Movement**: Identifies reconnaissance and lateral movement attempts
- **Advanced Persistent Threats**: Recognizes long-term, stealthy campaigns

**Configuration**: `"threat_hunting": true`

**Hunting Intervals**: Runs every 30 minutes analyzing recent traffic patterns

#### 4. Adaptive Blocking (Future Feature)
**Purpose**: AI learns from blocked threats to improve future detection.

**Capabilities**:
- **Pattern Learning**: Adapts to new threat patterns
- **False Positive Reduction**: Learns to distinguish threats from legitimate traffic
- **Dynamic Rule Generation**: Creates new blocking rules based on AI analysis
- **Contextual Blocking**: Considers client behavior and network context

**Configuration**: `"adaptive_blocking": false` (disabled by default)

### AI Analysis Process

#### 1. Domain Analysis Flow
```
DNS Request → Domain Extraction → AI Analysis → Threat Assessment → Block/Allow Decision
```

1. **Request Interception**: Capture DNS request before upstream resolution
2. **AI Prompt Generation**: Create cybersecurity-focused analysis prompt
3. **AI API Call**: Query configured AI provider with domain analysis request
4. **Response Processing**: Parse JSON response or extract key information
5. **Decision Making**: Apply confidence thresholds and blocking logic
6. **Caching**: Store results to reduce API costs and improve performance

#### 2. Traffic Pattern Analysis
```
DNS Traffic → Pattern Collection → Anomaly Scoring → AI Assessment → Alert Generation
```

1. **Pattern Collection**: Aggregate DNS requests into time-based windows
2. **Metric Calculation**: Compute request rates, domain diversity, timing patterns
3. **Heuristic Scoring**: Apply rule-based anomaly detection
4. **AI Enhancement**: Use AI to analyze complex patterns and correlations
5. **Threat Scoring**: Generate comprehensive threat assessment
6. **Action Taking**: Log alerts, trigger notifications, or block traffic

### Performance and Cost Optimization

#### Intelligent Caching
- **Multi-Tier Caching**: In-memory and Redis caching for AI results
- **TTL Management**: Configurable cache expiration based on threat type
- **Cache Warming**: Proactive caching of frequently requested domains
- **Cost Optimization**: Reduce AI API calls by up to 90%

#### Rate Limiting
- **Provider Limits**: Respect AI provider rate limits
- **Cost Controls**: Configurable maximum requests per minute
- **Priority Queuing**: Prioritize high-risk analysis requests
- **Graceful Degradation**: Fall back to heuristics when AI is unavailable

#### Batch Processing
- **Request Batching**: Group multiple domains for efficient analysis
- **Background Processing**: Non-blocking AI analysis for better performance
- **Async Operations**: Parallel processing of multiple AI requests

### Security and Privacy

#### Data Protection
- **No Data Retention**: AI providers don't retain dfirewall data
- **Minimal Context**: Only necessary information sent to AI
- **Local Processing**: Option to use local AI models for complete privacy
- **Encrypted Communication**: All API communications use HTTPS/TLS

#### Fail-Safe Design
- **Default Allow**: Network errors don't block legitimate traffic
- **Fallback Mechanisms**: Heuristic analysis when AI is unavailable
- **Confidence Thresholds**: Conservative blocking to minimize false positives
- **Override Capabilities**: Manual override of AI decisions

### Integration Examples

#### Enterprise SOC Integration
```bash
# Enable comprehensive AI analysis
AI_CONFIG=/config/ai-config.json
DEBUG=1  # Enable detailed AI logging

# Configure high-confidence blocking
{
  "confidence_threshold": 0.8,
  "domain_analysis": true,
  "traffic_anomaly": true,
  "threat_hunting": true
}
```

#### Cost-Conscious Deployment
```bash
# Use local AI model to avoid API costs
{
  "provider": "local",
  "base_url": "http://localhost:11434",
  "model": "llama2",
  "max_analysis_requests": 1000
}
```

#### Development and Testing
```bash
# Conservative settings for testing
{
  "enabled": true,
  "confidence_threshold": 0.9,
  "domain_analysis": true,
  "traffic_anomaly": false,
  "threat_hunting": false
}
```

### Monitoring and Observability

#### AI Analysis Logging
```
2024-07-30 15:30:45 AI BLOCK: Domain malicious-site.com flagged as malicious by AI (threat_score: 0.85, confidence: 0.92, reasoning: Phishing domain targeting financial services)
2024-07-30 15:31:12 AI ANOMALY DETECTED: Client 192.168.1.100 - Beaconing behavior detected with 95% confidence (15 requests to single domain every 60 seconds)
2024-07-30 15:32:01 AI THREAT HUNTING ALERT: Campaign detected across 3 clients requesting DGA domains (confidence: 0.78)
```

#### Performance Metrics
- AI API response times
- Cache hit rates
- Blocking accuracy rates
- Cost per analysis request
- Threat detection rates

### Use Cases

#### Advanced Persistent Threat (APT) Detection
- **Long-term Surveillance**: AI identifies subtle patterns over extended periods
- **Campaign Correlation**: Connects related activities across multiple clients
- **Behavioral Analysis**: Recognizes human vs. automated attack patterns
- **Zero-Day Protection**: Detects novel attack techniques before signature updates

#### Insider Threat Detection
- **Anomalous Behavior**: Identifies unusual DNS patterns from internal users
- **Data Exfiltration**: Detects potential data theft through DNS patterns
- **Privilege Escalation**: Recognizes reconnaissance and lateral movement attempts
- **Policy Violations**: Identifies unauthorized network access attempts

#### Industrial IoT Security
- **Device Profiling**: AI learns normal behavior patterns for IoT devices
- **Compromise Detection**: Identifies when devices deviate from normal patterns
- **Botnet Prevention**: Detects IoT devices joining botnets or C&C networks
- **Firmware Analysis**: Analyzes update and communication patterns

#### Cloud Security Enhancement
- **Multi-Tenant Analysis**: AI analyzes patterns across cloud deployments
- **Container Security**: Monitors DNS patterns from containerized workloads
- **Serverless Monitoring**: Tracks DNS requests from serverless functions
- **Cloud-Native Threats**: Identifies cloud-specific attack patterns

## Custom Script Integration

dfirewall supports user-provided pass/fail scripts for custom domain and IP validation, allowing organizations to implement proprietary security logic, business rules, and compliance requirements.

### Configuration

Create a custom script configuration file and set `CUSTOM_SCRIPT_CONFIG=/path/to/custom-script-config.json`:

```json
{
  "enabled": true,
  "unified_script": "/scripts/custom_validate.sh",
  "domain_script": "",
  "ip_script": "",
  
  "timeout": 10,
  "retry_count": 1,
  "cache_results": true,
  "cache_ttl": 300,
  
  "failure_mode": "allow",
  "log_decisions": true,
  "log_failures": true
}
```

### Script Types

#### Unified Script
- **Purpose**: Single script handles both domain and IP validation
- **Configuration**: `"unified_script": "/path/to/script.sh"`
- **Precedence**: Takes priority over separate domain/IP scripts
- **Use Case**: Simplified deployment with shared validation logic

#### Separate Scripts
- **Domain Script**: `"domain_script": "/path/to/domain_script.sh"`
- **IP Script**: `"ip_script": "/path/to/ip_script.sh"`
- **Use Case**: Specialized validation logic for each target type

### Script Interface

#### Command Line Arguments
```bash
script.sh <target> <type>
```
- **`<target>`**: Domain name or IP address to validate
- **`<type>`**: Either "domain" or "ip"

#### Environment Variables
Scripts receive additional context through environment variables:
- **`DFIREWALL_TARGET`**: Same as first argument
- **`DFIREWALL_TYPE`**: Same as second argument  
- **`DFIREWALL_TIMESTAMP`**: Unix timestamp when script was called

#### Exit Codes
- **`0`**: Allow (target is safe)
- **`1`**: Block (target should be blocked)
- **Any other code**: Block (treated as block decision)

#### Output Handling
- **stdout**: Captured and logged (decision reasoning)
- **stderr**: Captured and logged (error messages)

### Example Scripts

#### Unified Validation Script
```bash
#!/bin/bash
TARGET="$1"
TYPE="$2"

case "$TYPE" in
    "domain")
        # Block domains containing suspicious keywords
        if echo "$TARGET" | grep -qi -E "(malicious|evil|phishing)"; then
            echo "BLOCK: Domain contains suspicious keywords" 
            exit 1
        fi
        
        # Block very long subdomains (potential DGA)
        SUBDOMAIN=$(echo "$TARGET" | cut -d'.' -f1)
        if [ ${#SUBDOMAIN} -gt 20 ]; then
            echo "BLOCK: Subdomain suspiciously long"
            exit 1
        fi
        ;;
        
    "ip")
        # Block private IPs in external DNS responses
        if echo "$TARGET" | grep -q -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
            echo "BLOCK: Private IP in external DNS"
            exit 1
        fi
        
        # Block network/broadcast addresses
        if echo "$TARGET" | grep -q -E "\.(0|255)$"; then
            echo "BLOCK: Network or broadcast address"
            exit 1
        fi
        ;;
esac

echo "ALLOW: Validation passed"
exit 0
```

#### Domain-Specific Script
```bash
#!/bin/bash
DOMAIN="$1"

# Load blocked domains from file
if grep -q "^$DOMAIN$" /etc/dfirewall/blocked_domains.txt; then
    echo "BLOCK: Domain in blocked list"
    exit 1  
fi

# Check domain against internal policy
if echo "$DOMAIN" | grep -qi "\.adult\|\.gambling\|\.social"; then
    echo "BLOCK: Violates corporate policy"
    exit 1
fi

# Time-based blocking
HOUR=$(date +%H)
if [ "$HOUR" -ge 9 ] && [ "$HOUR" -le 17 ]; then
    if echo "$DOMAIN" | grep -qi "entertainment\|games\|social"; then
        echo "BLOCK: Non-business site during work hours"
        exit 1
    fi
fi

echo "ALLOW: Domain approved"
exit 0
```

### Configuration Options

#### Execution Settings
- **`timeout`**: Maximum script execution time (1-300 seconds)
- **`retry_count`**: Number of retries on script failure (0-5)
- **`cache_results`**: Enable result caching for performance
- **`cache_ttl`**: Cache expiration time in seconds

#### Error Handling  
- **`failure_mode`**: Action on script failure ("allow" or "block")
- **`log_decisions`**: Log all script decisions
- **`log_failures`**: Log script execution failures

### Integration Flow

#### Domain Validation Flow
```
DNS Request → Domain Extraction → Custom Script → Block/Allow Decision
```

1. **Request Interception**: Domain extracted from DNS request
2. **Script Execution**: Custom script called with domain and "domain" type
3. **Result Processing**: Exit code interpreted as allow/block decision
4. **Caching**: Result cached if enabled
5. **Action**: NXDOMAIN returned for blocked domains

#### IP Validation Flow  
```
DNS Resolution → IP Extraction → Custom Script → Include/Exclude from Response
```

1. **IP Extraction**: IPs extracted from DNS response
2. **Script Execution**: Custom script called with IP and "ip" type  
3. **Result Processing**: Exit code determines IP inclusion
4. **Filtering**: Blocked IPs removed from DNS response
5. **Caching**: Result cached for future requests

### Performance Optimization

#### Caching Strategy
- **Target-Based Caching**: Results cached by domain/IP
- **TTL Management**: Configurable cache expiration
- **Memory Efficiency**: LRU eviction for large caches
- **Cache Warming**: Proactive caching of common targets

#### Execution Optimization
- **Timeout Protection**: Prevents hanging scripts
- **Retry Logic**: Handles transient failures
- **Concurrent Execution**: Non-blocking script execution
- **Resource Limits**: Prevents resource exhaustion

### Security Considerations

#### Script Security
- **Execution Permissions**: Scripts must be executable by dfirewall user
- **Path Validation**: Script paths validated at startup
- **Environment Isolation**: Scripts run in controlled environment
- **Input Sanitization**: Arguments sanitized for shell safety

#### Error Handling
- **Fail-Safe Default**: Configurable failure mode (allow/block)
- **Timeout Handling**: Scripts killed on timeout
- **Resource Protection**: Prevents script resource abuse
- **Logging**: Comprehensive execution logging

### Use Cases

#### Corporate Policy Enforcement
```bash
# Block social media during work hours
HOUR=$(date +%H)
if [ "$HOUR" -ge 9 ] && [ "$HOUR" -le 17 ]; then
    if echo "$TARGET" | grep -qi "facebook\|twitter\|instagram"; then
        echo "BLOCK: Social media blocked during work hours"
        exit 1
    fi
fi
```

#### Compliance Requirements
```bash
# HIPAA compliance - block unauthorized health sites
if echo "$TARGET" | grep -qi "health\|medical" && ! echo "$TARGET" | grep -qi "approved-medical.com"; then
    echo "BLOCK: Unauthorized medical site"
    exit 1
fi
```

#### Geographic Restrictions
```bash
# Block IPs from certain countries (using GeoIP)
COUNTRY=$(geoiplookup "$TARGET" | cut -d':' -f2 | tr -d ' ')
if echo "$COUNTRY" | grep -qi "CN\|RU\|KP"; then
    echo "BLOCK: IP from restricted country: $COUNTRY"
    exit 1
fi
```

#### Threat Intelligence Integration
```bash
# Check against custom threat feeds
if curl -s "https://internal-threat-intel.company.com/check?target=$TARGET" | grep -q "malicious"; then
    echo "BLOCK: Flagged by internal threat intelligence"
    exit 1
fi
```

#### Content Filtering
```bash
# Parental controls - block adult content
if echo "$TARGET" | grep -qi -f /etc/dfirewall/adult_keywords.txt; then
    echo "BLOCK: Adult content blocked"
    exit 1
fi
```

### Monitoring and Debugging

#### Logging Examples
```
2024-07-30 15:45:12 CUSTOM SCRIPT BLOCK: Domain gambling.com requested by 192.168.1.100 blocked by custom script (exit_code: 1, execution_time: 0.023s, output: BLOCK: Violates corporate policy)
2024-07-30 15:45:15 CUSTOM SCRIPT OK: Domain google.com allowed by custom script (exit_code: 0, execution_time: 0.012s)
2024-07-30 15:45:18 CUSTOM SCRIPT ERROR: Failed to execute script for badsite.com (domain): script execution timeout after 10 seconds
```

#### Performance Metrics
- Script execution time statistics
- Cache hit rates
- Failure rates and timeout occurrences
- Decision distribution (allow vs block)

### Advanced Features

#### Dynamic Script Loading
- **Hot Reload**: Update scripts without restarting dfirewall
- **Version Control**: Track script changes and rollbacks
- **A/B Testing**: Compare different validation logic

#### Script Chaining
- **Multiple Scripts**: Execute multiple validation scripts
- **Decision Logic**: AND/OR logic for multiple script results
- **Priority Ordering**: Execute scripts in priority order

#### Integration APIs
- **REST API**: HTTP endpoints for script management
- **Database Integration**: Store validation rules in databases
- **External Services**: Call external validation services


# ToDo
- ~~fix EDNS handling~~ ✅ **Completed** - Fixed EDNS Client Subnet with IPv4/IPv6 support and proper validation
- ~~add support for handling all IPs in a response (rather than selecting first IP only)~~ ✅ **Completed** - Added `HANDLE_ALL_IPS` environment variable option
- ~~add AAAA records (IPv6 support)~~ ✅ **Completed** - Added AAAA record processing for IPv6 addresses
- ~~add Redis key expiration triggering or a watchdog (to enable non-Linux / non-ipset support)~~ ✅ **Completed** - Added `EXPIRE_SCRIPT` with Redis keyspace notifications monitoring
- ~~add UI for viewing rules~~ ✅ **Completed** - Added web-based UI with rule viewing, statistics, and management features
- ~~add better configuration options (invoke custom script(s) per client (if exist), etc)~~ ✅ **Completed** - Added JSON-based per-client script configuration with pattern matching
- ~~add support for checking IP and/or domain against blacklist in Redis (or file)~~ ✅ **Completed** - Added comprehensive Redis and file-based IP/domain blacklisting
- ~~add support for checking IP and/or domain against common reputation checkers~~ ✅ **Completed** - Added integration with VirusTotal, AbuseIPDB, URLVoid, and custom reputation services
- ~~AI integration~~ ✅ **Completed** - Added comprehensive AI-powered threat detection with domain analysis, traffic anomaly detection, and proactive threat hunting :D
- ~~add support for checking IP and/or domain by executing user-provided pass/fail script~~ ✅ **Completed** - Added comprehensive custom script integration with unified/separate scripts, caching, retry logic, and extensive configuration options
- Please add functionality to the Web UI to add an IP or a domain to the Redis blacklist immediately
- Please add Web UI functionality to perform reputation checking and AI detection for an IP or a domain ad hoc
- Please expose all Web UI actions as REST API
- Add TLS certificate and password authentication capability to Redis
- Add Web UI HTTPS, Password, and LDAP authentication support
