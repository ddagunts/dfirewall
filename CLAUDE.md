# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dfirewall is a DNS proxy that implements a "default deny" egress network firewall. It monitors DNS requests and responses, tracks IP addresses and TTLs via Redis, and executes firewall management scripts to dynamically allow outbound connections only to resolved IPs.

## Architecture

### Core Components

- **dfirewall.go**: Main entry point that starts UDP and TCP DNS servers on port 53 (64 lines)
- **proxy.go**: DNS proxy logic that handles requests, queries upstream DNS, stores results in Redis, and executes firewall scripts (~1300+ lines)
- **sni.go**: SNI (Server Name Indication) inspection system with TLS connection interception, validation, and proxying (~650+ lines)
- **logcollector.go**: Log collection system with SSH and local file monitoring, regex pattern matching, and integration with firewall rules (~900+ lines)
- **api.go**: HTTP API handlers for web UI and REST endpoints (~1200+ lines)
- **webui.go**: Web UI server with authentication middleware and rate limiting (~400+ lines)
- **auth.go**: Authentication system supporting password, LDAP, and header-based auth (~500+ lines)
- **redis.go**: Redis client management with TLS and authentication support (~300+ lines)
- **security.go**: Security validation, blacklisting, reputation checking, and AI threat detection (~2400+ lines)
- **types.go**: Data structures and configuration types (~700+ lines)
- **scripts/**: Shell scripts for firewall management, expiration handling, and validation (8 scripts)
- **config/**: Example and active configuration files (12+ JSON/text files)
- **docs/**: Comprehensive documentation (10 markdown files)

### Architecture Flow

1. **DNS Interception**: Client DNS requests → dfirewall:53 → upstream resolver
2. **Data Processing**: DNS responses → IP/domain extraction → Redis storage with TTL
3. **Historical Tracking**: Each DNS lookup → client history storage in Redis sorted sets → time-based indexing for efficient querying
4. **SNI Inspection**: If enabled, return proxy IP instead of real IP → track DNS mapping → intercept TLS connections → validate SNI headers
5. **Security Pipeline**: IPs/domains → blacklist check → reputation check → AI analysis → custom scripts
6. **Firewall Integration**: Validated IPs → script execution → iptables/ipset rules → client access
7. **Log Collection**: Remote/local log files → regex extraction → security pipeline → firewall rules
8. **Expiration**: Redis TTL expires → expire script → cleanup firewall rules

### Key Features

- DNS interception and forwarding to upstream resolvers
- **Per-client and per-zone upstream resolver routing with priority-based selection**
- **SNI (Server Name Indication) inspection with TLS connection interception to detect domain fronting and DNS abuse**
- Redis storage for tracking client IP → resolved IP → domain mappings with TTL expiration
- **Comprehensive historical DNS lookup tracking with per-client query history, time-range filtering, and automatic data retention management**
- Dynamic firewall rule creation via executable scripts
- Per-client script configuration with pattern matching (IP, CIDR, regex)
- IP and domain blacklisting with Redis and file-based support
- IP and domain reputation checking with multiple threat intelligence providers (VirusTotal, AbuseIPDB, URLVoid, custom APIs)
- AI-powered threat detection with domain analysis, traffic anomaly detection, and proactive threat hunting (OpenAI, Claude, local models) :D
- Custom script integration for user-provided pass/fail validation with unified/separate scripts, caching, and retry logic
- Redis key expiration monitoring with cleanup scripts (enables non-Linux/non-ipset support)
- **Log collection from remote and local sources via SSH and local file monitoring with regex pattern matching for IP/domain extraction**
- Web-based UI for viewing and managing firewall rules with historical query analysis
- Support for both UDP and TCP DNS protocols
- Support for both IPv4 (A records) and IPv6 (AAAA records)
- Client IP detection and per-client rule management

## Development Commands

### Building and Testing

```bash
# IMPORTANT: Always use Docker Compose for all builds and tests (required for Redis integration and consistent environment)
# Build with Docker Compose
docker-compose up --build -d

# IMPORTANT: Always run tests using Docker Compose (required for Redis integration)
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Run specific security tests
# Edit docker-compose.test.yml command line to target specific tests:
# command: ["go", "test", "-v", "-run", "TestValidationFunctionsAgainstShellInjection|TestExploitAttempts", "./..."]

# Format code (run inside container or use Docker)
docker-compose exec dfirewall go fmt ./...

# Vet code for issues (run inside container or use Docker)  
docker-compose exec dfirewall go vet ./...

# Download dependencies (handled by Docker build)
# go mod download

# Tidy dependencies (handle via Docker if needed)
# go mod tidy
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
- `SYNC_SCRIPT_EXECUTION`: Execute scripts synchronously to ensure firewall rules are created before DNS response (global fallback)
- `EXPIRE_SCRIPT`: Path to executable script for cleanup when Redis keys expire (global fallback)
- `SCRIPT_CONFIG`: Path to JSON configuration file for per-client script settings
- `UPSTREAM_CONFIG`: Path to JSON configuration file for per-client/zone upstream DNS routing
- `TTL_GRACE_PERIOD_SECONDS`: Default grace period added to all DNS TTLs before firewall rules expire (default: 90). Can be overridden per-client via SCRIPT_CONFIG
- `HISTORY_RETENTION_DAYS`: Number of days to retain client DNS lookup history (default: 30). Historical data is stored in Redis sorted sets with automatic expiration
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
- `SNI_INSPECTION_CONFIG`: Path to JSON configuration file for SNI (TLS) inspection and domain fronting detection
- `HANDLE_ALL_IPS`: When set, process all A records in DNS response instead of just the first one
- `ENABLE_EDNS`: Enable EDNS client subnet with proper IPv4/IPv6 support
- `DEBUG`: Enable verbose logging

## Code Organization

**Codebase Statistics (Current)**
- **Total Go Code**: ~13,157 lines across 19 Go files
- **Test Files**: 11 comprehensive test files with 89+ test functions
- **Configuration**: 10+ JSON configuration files with examples
- **Documentation**: 9 detailed markdown files in docs/ directory
- **Scripts**: 8 shell scripts for firewall and validation operations

### Configuration Management
- All JSON configs are in `config/` with `.example.json` files showing structure
- Configuration structs are centralized in `types.go` (700+ lines)
- Environment variable processing in `proxy.go` during startup via `Register()` function
- Configuration validation functions per feature (e.g., `validateLogSource()` in logcollector.go)
- Real-time configuration status available via `/api/config/status` endpoint

### Security Pipeline
- Input validation in `security.go` with `validateForShellExecution()` (security.go:1917-2033)
- Blacklisting: Redis-based and file-based, configured via `BLACKLIST_CONFIG`
- Reputation checking: Multiple providers (VirusTotal, AbuseIPDB, URLVoid, custom), configured via `REPUTATION_CONFIG`
- AI analysis: OpenAI/Claude/local model integration, configured via `AI_CONFIG`
- Custom scripts: User-provided validation, configured via `CUSTOM_SCRIPT_CONFIG`
- SNI inspection: TLS connection interception and domain fronting detection, configured via `SNI_INSPECTION_CONFIG`
- Memory safety: Bounded caches with automatic cleanup (security.go:2259-2434)

### Authentication System
- Multi-method auth: password, LDAP, header-based (auth.go)
- Session management with JWT tokens and secure secrets
- Rate limiting: 60 requests/minute general, 5 login attempts/minute (webui.go:12-45)
- Middleware pattern in `webui.go` for protecting endpoints
- TLS/HTTPS support for web UI with certificate management

### Data Flow Patterns
- **Firewall Rules**: Redis keys use format: `rules:clientIP|resolvedIP|domain` (pipe-separated for IPv6 safety)
- **Historical Data**: Redis sorted sets use format: `history:client:{clientIP}` with Unix timestamp scoring for efficient time-range queries
- TTL inheritance: DNS TTL → Redis TTL → firewall rule TTL (clamped to 3600s max)
- **History Retention**: Configurable automatic expiration (default: 30 days) with background cleanup
- Script execution: configurable sync/async with validation, timeout (30s), and environment variables
- Error handling: graceful degradation, structured logging, continue on non-critical failures
- CNAME security: Uses originally requested domain for blacklist checks, not resolved CNAME target

### Testing Strategy
- Unit tests per module: 11 `*_test.go` files with 89+ test functions
- Integration tests for DNS proxy functionality
- Security validation tests for shell injection prevention (security_validation_test.go)
- API endpoint tests with mock Redis clients
- Comprehensive CNAME blacklist bypass testing (cname_blacklist_test.go)
- Redis key validation testing (redis_key_validation_test.go)

### Dependencies

- **Go 1.24+** (current module requirement)
- **Redis 7.2+** (Redis server with keyspace notifications for expiration monitoring)
- **Linux with iptables and ipset** (for firewall functionality, optional - scripts can use APIs/SSH)
- **SSH access** (for remote log collection and firewall management)
- **Docker & Docker Compose** (recommended deployment method)

**Key Go Dependencies:**
- `github.com/miekg/dns v1.1.68` - DNS protocol implementation
- `github.com/redis/go-redis/v9 v9.11.0` - Redis client with TLS support
- `github.com/golang-jwt/jwt/v5 v5.3.0` - JWT token handling
- `github.com/go-ldap/ldap/v3 v3.4.11` - LDAP authentication
- `github.com/fsnotify/fsnotify v1.9.0` - File system monitoring
- `golang.org/x/crypto v0.40.0` - SSH and cryptographic functions

## Docker Deployment

**Current Docker Configuration:**
- **Base Images**: golang:1.24 (build stage), debian:bookworm (runtime)
- **Redis**: redis:7.2-alpine container with health checks
- **Networking**: Host mode for DNS interception (exposes WEB_UI_PORT)
- **Security**: read-only filesystem, tmpfs for /tmp and /dev/shm, no-new-privileges
- **Capabilities**: NET_ADMIN (can be removed for unprivileged deployment with SSH-based scripts)
- **User**: Configurable - defaults to nobody:nogroup, can override to root for demo
- **Ports**: DNS (53/udp, 53/tcp), Web UI (configurable via WEB_UI_PORT)
- **Volumes**: Scripts and config directories mounted
- **Health Checks**: Redis health monitoring with automatic restart
- **Dependencies**: dfirewall waits for Redis to be healthy before starting

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
- **Client DNS history**: `history:client:{clientIP}` (Redis sorted sets with Unix timestamp scores)
- Blacklists: `dfirewall:blacklist:ips`, `dfirewall:blacklist:domains` (Redis sets)
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

## Web UI API Endpoints

The Web UI provides a comprehensive REST API for managing firewall rules and security features:

### Core API Endpoints
- `/api/rules` - List firewall rules (supports grouped view)
- `/api/stats` - System statistics and metrics
- `/api/rules/delete` - Delete specific firewall rules
- `/api/health` - System health status
- `/api/docs` - API documentation
- `/api/config/status` - Configuration status (with credential sanitization)

### Historical Query Management APIs
- `/api/client/history/{clientIP}` - Get comprehensive historical DNS lookups for a specific client
  - **Time Range Filtering**: Query by start/end timestamps or relative time periods (1 day, 3 days, 7 days, 30 days)
  - **Result Limiting**: Configurable result limits (100, 500, 1000, 5000 lookups)
  - **Data Format**: Returns structured data with timestamp, domain, resolved IPs, and TTL information
  - **Automatic Retention**: Historical data automatically expires based on `HISTORY_RETENTION_DAYS` (default: 30 days)
  - **Performance Optimized**: Uses Redis sorted sets with time-based scoring for efficient range queries

### Security Management APIs
- `/api/blacklist/ip/add` - Add IP to blacklist
- `/api/blacklist/ip/remove` - Remove IP from blacklist
- `/api/blacklist/domain/add` - Add domain to blacklist
- `/api/blacklist/domain/remove` - Remove domain from blacklist
- `/api/blacklist/list` - List current blacklists
- `/api/reputation/check` - Check IP/domain reputation
- `/api/ai/analyze` - AI-powered threat analysis

### Log Collection APIs
- `/api/logcollector/stats` - Log collector statistics
- `/api/logcollector/config` - Log collector configuration

### SNI Inspection APIs
- `/api/sni/stats` - SNI inspection statistics and connection metrics
- `/api/sni/connections` - List active SNI connections
- `/api/sni/config` - SNI inspection configuration
- `/api/sni/validate` - Validate specific client/domain/SNI combinations

### Authentication Endpoints
- `/login` - User authentication (rate limited: 5 attempts/minute)
- `/logout` - Session termination

All API endpoints (except login/logout) require authentication and are rate limited (60 requests/minute per IP).

## Recent Security Improvements (2025)

### Pattern Matching Unification
Recent updates have unified domain pattern matching across all features:
- **Shared Function**: `matchesDomainPattern()` in `security.go:1931-1962` provides consistent matching
- **Wildcard Support**: `*.example.com` patterns work in both upstream routing and blacklists
- **CNAME Security**: Fixed blacklist bypass where CNAME resolution could circumvent blocking (proxy.go:574-580)
- **Redis Consistency**: Redis and file-based blacklists now have identical pattern support

### Domain Blacklist Security Fixes
- **CNAME Bypass Prevention**: Domain blacklisting now uses originally requested domain, not resolved CNAME target
- **Redis Parent Domain Support**: Redis blacklists now support parent domain blocking (e.g., `evil.com` blocks `www.evil.com`)
- **Pattern Consistency**: Wildcard and regex patterns work consistently across Redis and file-based blacklists

### Memory Safety & Performance
- **Bounded Caches**: All caches have configurable size limits (default: 10,000 entries) with automatic cleanup
- **Rate Limiting**: Built-in protection against brute force attacks (60 requests/minute general, 5 login attempts/minute)
- **API Security**: Comprehensive credential sanitization in configuration status endpoints
- **Resource Management**: Script execution timeouts, cleanup routines, graceful shutdown handling

### SNI Inspection & Domain Fronting Detection (2025)
- **TLS Connection Interception**: New SNI inspection system intercepts TLS connections to validate domain authenticity
- **Domain Fronting Protection**: Detects when clients resolve one domain but connect to another via SNI header manipulation
- **Per-Client/Domain Policies**: Flexible configuration allowing SNI inspection to be enabled selectively based on client IPs or domain patterns
- **Real-time Monitoring**: Comprehensive statistics and active connection tracking with API endpoints for management
- **Security Integration**: Seamlessly integrates with existing blacklisting, reputation checking, and AI analysis features

### Testing & Validation
- **Security Test Coverage**: 110+ test functions including comprehensive shell injection prevention tests and SNI inspection validation
- **CNAME Security Testing**: Dedicated test suite for CNAME blacklist bypass scenarios
- **Redis Key Validation**: Extensive testing for Redis key parsing and validation security
- **SNI Inspection Tests**: Complete test suite for TLS ClientHello parsing, domain validation, and proxy functionality