# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dfirewall is a DNS proxy that implements a "default deny" egress network firewall. It monitors DNS requests and responses, tracks IP addresses and TTLs via Redis, and executes firewall management scripts to dynamically allow outbound connections only to resolved IPs.

## Architecture

### Core Components

- **dfirewall.go**: Main entry point that starts UDP and TCP DNS servers on port 53
- **proxy.go**: DNS proxy logic that handles requests, queries upstream DNS, stores results in Redis, and executes firewall scripts
- **logcollector.go**: Log collection system with SSH and local file monitoring, regex pattern matching, and integration with firewall rules
- **api.go**: HTTP API handlers for web UI and REST endpoints
- **webui.go**: Web UI server with authentication middleware
- **auth.go**: Authentication system supporting password, LDAP, and header-based auth
- **redis.go**: Redis client management with TLS and authentication support
- **security.go**: Security validation, blacklisting, reputation checking, and AI threat detection
- **types.go**: Data structures and configuration types
- **scripts/**: Shell scripts for firewall management, expiration handling, and validation

### Architecture Flow

1. **DNS Interception**: Client DNS requests → dfirewall:53 → upstream resolver
2. **Data Processing**: DNS responses → IP/domain extraction → Redis storage with TTL
3. **Security Pipeline**: IPs/domains → blacklist check → reputation check → AI analysis → custom scripts
4. **Firewall Integration**: Validated IPs → script execution → iptables/ipset rules → client access
5. **Log Collection**: Remote/local log files → regex extraction → security pipeline → firewall rules
6. **Expiration**: Redis TTL expires → expire script → cleanup firewall rules

### Key Features

- DNS interception and forwarding to upstream resolvers
- **Per-client and per-zone upstream resolver routing with priority-based selection**
- Redis storage for tracking client IP → resolved IP → domain mappings with TTL expiration
- Dynamic firewall rule creation via executable scripts
- Per-client script configuration with pattern matching (IP, CIDR, regex)
- IP and domain blacklisting with Redis and file-based support
- IP and domain reputation checking with multiple threat intelligence providers (VirusTotal, AbuseIPDB, URLVoid, custom APIs)
- AI-powered threat detection with domain analysis, traffic anomaly detection, and proactive threat hunting (OpenAI, Claude, local models) :D
- Custom script integration for user-provided pass/fail validation with unified/separate scripts, caching, and retry logic
- Redis key expiration monitoring with cleanup scripts (enables non-Linux/non-ipset support)
- **Log collection from remote and local sources via SSH and local file monitoring with regex pattern matching for IP/domain extraction**
- Web-based UI for viewing and managing firewall rules
- Support for both UDP and TCP DNS protocols
- Support for both IPv4 (A records) and IPv6 (AAAA records)
- Client IP detection and per-client rule management

## Development Commands

### Building and Testing

```bash
# Build the Go binary
go build -o dfirewall

# IMPORTANT: Always run tests using Docker Compose (required for Redis integration)
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Run specific security tests
# Edit docker-compose.test.yml command line to target specific tests:
# command: ["go", "test", "-v", "-run", "TestValidationFunctionsAgainstShellInjection|TestExploitAttempts", "./..."]

# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Download dependencies
go mod download

# Tidy dependencies
go mod tidy
```

### Running

```bash
# Run locally (requires Redis and proper environment variables)
UPSTREAM=1.1.1.1:53 REDIS=redis://127.0.0.1:6379 ./dfirewall

# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs dfirewall
docker-compose logs redis

# Run with debug logging
DEBUG=1 ./dfirewall
```

### Configuration Testing

```bash
# Test configuration files (validate JSON syntax)
jq . config/blacklist-config.example.json

# Validate regex patterns in log collector config (manual validation required)
# Note: Pattern validation is performed at runtime when log collector starts
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
- `UPSTREAM_CONFIG`: Path to JSON configuration file for per-client/zone upstream DNS routing
- `TTL_GRACE_PERIOD_SECONDS`: Grace period added to all DNS TTLs before firewall rules expire (default: 90)
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
- `LOG_COLLECTOR_CONFIG`: Path to JSON configuration file for log collection from remote/local sources
- `HANDLE_ALL_IPS`: When set, process all A records in DNS response instead of just the first one
- `ENABLE_EDNS`: Enable EDNS client subnet with proper IPv4/IPv6 support
- `DEBUG`: Enable verbose logging

## Code Organization

### Configuration Management
- All JSON configs are in `config/` with `.example.json` files showing structure
- Configuration structs are centralized in `types.go`
- Environment variable processing in `proxy.go` during startup
- Configuration validation functions per feature (e.g., `validateLogSource()`)

### Security Pipeline
- Input validation in `security.go` with `validateForShellExecution()`
- Blacklisting: Redis-based and file-based, configured via `BLACKLIST_CONFIG`
- Reputation checking: Multiple providers (VirusTotal, AbuseIPDB), configured via `REPUTATION_CONFIG`
- AI analysis: OpenAI/Claude integration, configured via `AI_CONFIG`
- Custom scripts: User-provided validation, configured via `CUSTOM_SCRIPT_CONFIG`

### Authentication System
- Multi-method auth: password, LDAP, header-based
- Session management with JWT tokens
- Middleware pattern in `webui.go` for protecting endpoints
- TLS/HTTPS support for web UI

### Data Flow Patterns
- Redis keys use format: `rules:clientIP|resolvedIP|domain` (pipe-separated for IPv6 safety)
- TTL inheritance: DNS TTL → Redis TTL → firewall rule TTL (clamped to 3600s max)
- Script execution: async with validation, timeout (30s), and environment variables
- Error handling: graceful degradation, logging, continue on non-critical failures

### Testing Strategy
- Unit tests per module: `*_test.go` files
- Integration tests for DNS proxy functionality
- Security validation tests for shell injection prevention
- API endpoint tests with mock Redis clients

### Dependencies

- Go 1.24+
- Redis server (with keyspace notifications for expiration monitoring)
- Linux with iptables and ipset (for firewall functionality)
- SSH access for remote log collection

## Docker Deployment

The application runs in containers with:
- Redis container for state storage
- dfirewall container with NET_ADMIN capability for firewall management
- Host networking mode for intercepting DNS traffic
- Debian base image with iptables and ipset tools

## Security Considerations

This is experimental defensive security software intended for network egress control. The application requires elevated privileges (NET_ADMIN) to manage firewall rules and should only be deployed in controlled environments with proper network isolation.

## Upstream Resolver Configuration

dfirewall supports flexible upstream DNS resolver routing based on client IP addresses and domain patterns. This allows for sophisticated DNS forwarding policies.

### Configuration Priority

1. **Client-specific rules** (highest priority) - Route based on requesting client IP
2. **Zone-specific rules** (medium priority) - Route based on requested domain
3. **Default upstream** (lowest priority) - Fallback for unmatched requests

### Configuration File Format

Set `UPSTREAM_CONFIG` environment variable to a JSON configuration file:

```json
{
  "default_upstream": "1.1.1.1:53",
  "client_configs": [
    {
      "client_pattern": "192.168.1.0/24",
      "upstream": "8.8.8.8:53",
      "description": "Internal network uses Google DNS"
    },
    {
      "client_pattern": "^172\\.16\\..*",
      "upstream": "208.67.222.222:53",
      "description": "Docker network uses OpenDNS (regex)"
    }
  ],
  "zone_configs": [
    {
      "zone_pattern": "*.internal.company.com",
      "upstream": "10.0.1.10:53",
      "description": "Internal domains to internal DNS"
    },
    {
      "zone_pattern": "^.*\\.local$",
      "upstream": "127.0.0.1:5353",
      "description": ".local domains to mDNS (regex)"
    }
  ]
}
```

### Pattern Matching

**Client Patterns** support:
- **Exact IP**: `192.168.1.100`
- **CIDR notation**: `192.168.1.0/24`
- **Regex patterns**: `^172\\.16\\..*` (for complex matching)

**Zone Patterns** support:
- **Exact domain**: `example.com`
- **Wildcard**: `*.example.com` (matches subdomains and exact domain)
- **Regex patterns**: `^.*\\.local$` (for complex matching)

### Use Cases

- **Split-horizon DNS**: Internal domains to internal DNS, external to public DNS
- **Per-network routing**: Different subnets use different DNS servers
- **Security policies**: Route suspicious clients to filtered DNS services
- **Geographic routing**: Route based on client location to regional DNS servers
- **Development environments**: Route test domains to development DNS servers

## Important Implementation Notes

### Adding New Features
- Configuration structs go in `types.go`
- Environment variable loading in `proxy.go` Register() function
- Validation functions should follow `validate*()` naming pattern
- API endpoints: add handler in `api.go`, route in `webui.go`
- Always validate user input with `validateForShellExecution()` before script execution

### Redis Key Patterns
- Firewall rules: `rules:clientIP|resolvedIP|domain`
- Blacklists: `blacklist:ips`, `blacklist:domains` (Redis sets)
- Log collector stats: `logcollector:stats:*`
- AI cache: `ai:cache:*`
- Reputation cache: `reputation:cache:*`

### Script Integration
- Scripts receive: clientIP, resolvedIP, domain, TTL, action as arguments
- Environment variables: `DFIREWALL_*` plus user-configured ones
- Always execute scripts asynchronously to avoid blocking DNS responses
- Set 30-second timeout for all script executions
- Scripts should be idempotent for repeated calls

### Error Handling Philosophy  
- DNS proxy: never fail DNS requests due to auxiliary features
- Security features: fail closed (block on error) but log extensively
- Web UI: graceful degradation with user-friendly error messages
- Log collection: reconnect automatically, don't stop DNS service

## Recent Security Improvements

### Pattern Matching Unification
Recent updates have unified domain pattern matching across all features:
- **Shared Function**: `matchesDomainPattern()` in `security.go:1931-1962` provides consistent matching
- **Wildcard Support**: `*.example.com` patterns work in both upstream routing and blacklists
- **CNAME Security**: Fixed blacklist bypass where CNAME resolution could circumvent blocking
- **Redis Consistency**: Redis and file-based blacklists now have identical pattern support

### Domain Blacklist Security Fixes
- **CNAME Bypass Prevention**: Domain blacklisting now uses originally requested domain, not resolved CNAME target
- **Redis Parent Domain Support**: Redis blacklists now support parent domain blocking (e.g., `evil.com` blocks `www.evil.com`)
- **Pattern Consistency**: Wildcard and regex patterns work consistently across Redis and file-based blacklists