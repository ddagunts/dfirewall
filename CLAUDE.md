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
- `INVOKE_SCRIPT`: Path to executable script for firewall management
- `INVOKE_ALWAYS`: Execute script for every IP encounter (not just new ones)
- `EXPIRE_SCRIPT`: Path to executable script for cleanup when Redis keys expire (enables non-Linux/non-ipset support)
- `WEB_UI_PORT`: Port for web-based rule management interface (1024-65535)
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