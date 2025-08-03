# dfirewall

dns firewall, or dynamic firewall.

`this is experimental`

The intent of this software is to assist in implementing a "default deny" egress network policy at the edge with minimal impact to legitimate clients.

This is a DNS proxy intended to be placed in front of your DNS resolvers/forwarders (Pi-hole, etc).  It allows to keep track of network activity by monitoring DNS requests and responses ( IP addresses and TTLs ) through reliance on Redis and execution of scripts.
It allows to create an IP firewall with the following features:
 - Block outgoing connections by default
 - Force clients to perform their DNS lookups through our server (or stay blocked)
 - Allow clients outbound access to IPs resolved, with timed expiration of rules
 - Turns any DNS block into a firewall block

# Configuration

dfirewall is configured through environment variables and JSON configuration files for advanced features.

**📖 For comprehensive configuration guidance, see:** [docs/configuration.md](docs/configuration.md)

### Quick Start Configuration
```bash
# Required
UPSTREAM=1.1.1.1:53          # upstream DNS resolver
REDIS=redis://127.0.0.1:6379 # Redis connection string

# Optional
PORT=53                      # listening port
WEB_UI_PORT=8080            # web interface port
DEBUG=true                  # enable verbose logging
```
# Setup on Linux

dfirewall can be deployed as a network router with firewall capabilities on Linux systems.

**📖 For complete step-by-step setup instructions, see:** [docs/linux-setup.md](docs/linux-setup.md)

### Quick Docker Deployment
```bash
# Clone and run with Docker Compose
git clone https://github.com/ddagunts/dfirewall 
cd dfirewall
docker-compose up -d
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
You can also manually delete rules from the web UI
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

dfirewall supports secure Redis connections with TLS encryption and authentication. Configure basic authentication or advanced TLS encryption with client certificates.

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
The Web UI supports HTTPS encryption, password authentication, LDAP integration, and header-based authentication for reverse proxy setups.

**📖 For detailed authentication setup, see:** [docs/webui-authentication.md](docs/webui-authentication.md)

## Per-Client Script Configuration

dfirewall supports per-client script configuration for different firewall policies based on client identity using CIDR, IP, and regex pattern matching.

**📖 For detailed configuration, see:** [docs/per-client-scripts.md](docs/per-client-scripts.md)

## IP and Domain Blacklisting

dfirewall supports comprehensive IP and domain blacklisting using Redis and file-based approaches with pattern matching and Web UI management.

**📖 For detailed configuration, see:** [docs/blacklist-configuration.md](docs/blacklist-configuration.md)

## IP and Domain Reputation Checking

dfirewall integrates with VirusTotal, AbuseIPDB, URLVoid, and custom threat intelligence providers for real-time security analysis.

**📖 For detailed configuration, see:** [docs/reputation-checking.md](docs/reputation-checking.md)

## AI-Powered Threat Detection

dfirewall integrates AI technology (OpenAI, Claude, local models) for domain analysis, traffic anomaly detection, and proactive threat hunting.

**📖 For detailed configuration, see:** [docs/ai-threat-detection.md](docs/ai-threat-detection.md)

