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
TTL_GRACE_PERIOD_SECONDS=90 # grace period added to all DNS TTLs (default: 90)
DEBUG=true                  # enable verbose logging
```
# Setup on Linux

dfirewall can be deployed as a network router with firewall capabilities.  The easiest platform to do this on is Linux thanks to ipset.

**📖 For a quick-start demo setup on Linux see:** [docs/linux-setup.md](docs/linux-setup.md)

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
2. Execute your expire script when DNS TTLs + grace period expire
3. Pass the same environment variables as INVOKE_SCRIPT, plus `ACTION=EXPIRE`

**TTL Grace Period**: All DNS TTLs are extended with a configurable grace period (default 90 seconds) before firewall rules are removed. This prevents premature rule expiration and provides a buffer for DNS refresh cycles. Configure via `TTL_GRACE_PERIOD_SECONDS` environment variable.

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
<img width="1476" height="1268" alt="Screenshot from 2025-08-01 09-16-27" src="https://github.com/user-attachments/assets/2bd3206d-cc91-4bb6-b727-56ad53520b49" />

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

## Log Collection and Analysis

dfirewall can collect and analyze logs from remote and local sources to extract IP addresses and domains for firewall rule creation. This feature enables proactive security by monitoring various log sources and automatically adding discovered threats to the firewall.

### Key Features

- **Remote Log Collection**: SSH-based log collection from remote servers
- **Local File Monitoring**: Monitor local log files for changes
- **Regex Pattern Matching**: Extract IPs and domains using configurable regex patterns
- **Real-time Processing**: Process log entries as they appear
- **Security Pipeline Integration**: Extracted IPs/domains go through blacklist, reputation, AI, and custom script validation
- **Automatic Firewall Rules**: Valid threats automatically added to firewall rules

### Quick Start

```bash
# Enable log collection
LOG_COLLECTOR_CONFIG=/path/to/log-collector-config.json
```

**📖 For detailed configuration, see:** [docs/log-collection.md](docs/log-collection.md)

