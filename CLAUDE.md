# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dfirewall is a DNS proxy that implements a "default deny" egress network firewall. It monitors DNS requests and responses, tracks IP addresses and TTLs via Redis, and executes firewall management scripts to dynamically allow outbound connections only to resolved IPs.

## Architecture

### Core Components

- **dfirewall.go**: Main entry point that starts UDP and TCP DNS servers on port 53
- **proxy.go**: DNS proxy logic that handles requests, queries upstream DNS, stores results in Redis, and executes firewall scripts
- **scripts/invoke_linux_ipset.sh**: Linux firewall management script that creates ipsets and iptables rules per client

### Key Features

- DNS interception and forwarding to upstream resolvers
- Redis storage for tracking client IP → resolved IP → domain mappings with TTL expiration
- Dynamic firewall rule creation via executable scripts
- Per-client script configuration with pattern matching (IP, CIDR, regex)
- IP and domain blacklisting with Redis and file-based support
- IP and domain reputation checking with multiple threat intelligence providers (VirusTotal, AbuseIPDB, URLVoid, custom APIs)
- AI-powered threat detection with domain analysis, traffic anomaly detection, and proactive threat hunting (OpenAI, Claude, local models) :D
- Custom script integration for user-provided pass/fail validation with unified/separate scripts, caching, and retry logic
- Redis key expiration monitoring with cleanup scripts (enables non-Linux/non-ipset support)
- Web-based UI for viewing and managing firewall rules
- Support for both UDP and TCP DNS protocols
- Support for both IPv4 (A records) and IPv6 (AAAA records)
- Client IP detection and per-client rule management

## Development Commands

### Building and Running

```bash
# Build the Go binary
go build -o dfirewall

# Run locally (requires Redis and proper environment variables)
./dfirewall

# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs dfirewall
docker-compose logs redis
```

### Environment Variables

Required:
- `UPSTREAM`: Upstream DNS resolver (e.g., "1.1.1.1:53")
- `REDIS`: Redis connection string (e.g., "redis://127.0.0.1:6379")

Optional:
- `PORT`: Listening port (default: 53)
- `INVOKE_SCRIPT`: Path to executable script for firewall management (global fallback)
- `INVOKE_ALWAYS`: Execute script for every IP encounter (not just new ones, global fallback)
- `EXPIRE_SCRIPT`: Path to executable script for cleanup when Redis keys expire (global fallback)
- `SCRIPT_CONFIG`: Path to JSON configuration file for per-client script settings
- `BLACKLIST_CONFIG`: Path to JSON configuration file for IP/domain blacklisting
- `REPUTATION_CONFIG`: Path to JSON configuration file for IP/domain reputation checking
- `AI_CONFIG`: Path to JSON configuration file for AI-powered threat detection :D
- `CUSTOM_SCRIPT_CONFIG`: Path to JSON configuration file for user-provided pass/fail scripts
- `WEB_UI_PORT`: Port for web-based rule management interface (1024-65535)
- `WEBUI_AUTH_CONFIG`: Path to JSON configuration file for Web UI authentication settings
- `WEBUI_HTTPS_ENABLED`: Enable HTTPS for Web UI (true/false)
- `WEBUI_CERT_FILE`: Path to TLS certificate file for HTTPS
- `WEBUI_KEY_FILE`: Path to TLS private key file for HTTPS
- `WEBUI_PASSWORD_AUTH`: Enable password authentication (true/false)
- `WEBUI_USERNAME`: Username for password authentication
- `WEBUI_PASSWORD`: Password for authentication (will be hashed automatically)
- `WEBUI_LDAP_AUTH`: Enable LDAP authentication (true/false)
- `WEBUI_LDAP_SERVER`: LDAP server hostname
- `WEBUI_LDAP_PORT`: LDAP server port (default: 389)
- `WEBUI_LDAP_BASE_DN`: LDAP base DN for user search
- `WEBUI_LDAP_BIND_DN`: LDAP bind DN for service account
- `WEBUI_LDAP_BIND_PASS`: LDAP bind password for service account
- `WEBUI_LDAP_USER_ATTR`: LDAP user attribute (default: uid)
- `WEBUI_LDAP_SEARCH_FILTER`: LDAP search filter for users
- `WEBUI_HEADER_AUTH`: Enable header-based authentication (true/false)
- `WEBUI_HEADER_NAME`: HTTP header name to check for authentication
- `WEBUI_HEADER_VALUES`: Comma-separated list of valid header values
- `WEBUI_TRUSTED_PROXIES`: Comma-separated list of trusted proxy IPs/CIDRs
- `WEBUI_SESSION_SECRET`: Secret key for session signing (auto-generated if not provided)
- `WEBUI_SESSION_EXPIRY`: Session expiry time in hours (default: 24)
- `SSH_LOG_CONFIG`: Path to JSON configuration file for SSH log monitoring
- `HANDLE_ALL_IPS`: When set, process all A records in DNS response instead of just the first one
- `ENABLE_EDNS`: Enable EDNS client subnet with proper IPv4/IPv6 support
- `DEBUG`: Enable verbose logging

### Dependencies

- Go 1.24.5+
- Redis server
- Linux with iptables and ipset (for firewall functionality)

## Docker Deployment

The application runs in containers with:
- Redis container for state storage
- dfirewall container with NET_ADMIN capability for firewall management
- Host networking mode for intercepting DNS traffic
- Debian base image with iptables and ipset tools

## Security Considerations

This is experimental defensive security software intended for network egress control. The application requires elevated privileges (NET_ADMIN) to manage firewall rules and should only be deployed in controlled environments with proper network isolation.