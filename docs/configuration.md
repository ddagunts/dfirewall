# Configuration Guide

This document provides comprehensive guidance for configuring dfirewall through environment variables and configuration files.

## Environment Variables

Configuration is handled through environmental variables. The following variables are available:

### Core Configuration (Required)
```bash
UPSTREAM=8.8.8.8:53          # upstream DNS resolver host and port (REQUIRED)
REDIS=redis://127.0.0.1:6379 # location of Redis (REQUIRED)
```

### Optional Core Settings
```bash
PORT=53                       # listening port (default: 53)
DEBUG=true                    # enable verbose logging
ENABLE_EDNS=true              # enable EDNS Client Subnet with requesting client IP (supports IPv4/IPv6)
HANDLE_ALL_IPS=true           # process all A records in DNS response instead of just the first one
```

### Advanced Upstream Configuration
```bash
UPSTREAM_CONFIG=              # path to JSON configuration file for per-client/zone upstream routing
TTL_GRACE_PERIOD_SECONDS=90   # grace period added to all DNS TTLs in seconds (default: 90)
```

**📖 For detailed upstream routing configuration, see:** [Advanced Upstream Configuration](#upstream-configuration-upstream_config)

### Redis Security Configuration
```bash
REDIS_PASSWORD=               # Redis authentication password (overrides URL password)
REDIS_TLS=true                # enable TLS/SSL connection to Redis (true/1/enabled)
REDIS_TLS_CERT=               # path to client certificate file for mutual TLS
REDIS_TLS_KEY=                # path to client private key file for mutual TLS
REDIS_TLS_CA=                 # path to CA certificate file for server verification
REDIS_TLS_SERVER_NAME=        # override server name for TLS certificate verification
REDIS_TLS_SKIP_VERIFY=        # skip TLS certificate verification (NOT recommended for production)
```

**📖 For detailed Redis security setup, see:** [docs/redis-security.md](docs/redis-security.md)

### Redis Performance Configuration
```bash
REDIS_MAX_RETRIES=3           # maximum connection retry attempts
REDIS_DIAL_TIMEOUT=5s         # connection establishment timeout
REDIS_READ_TIMEOUT=3s         # read operation timeout
REDIS_WRITE_TIMEOUT=3s        # write operation timeout
REDIS_POOL_SIZE=10            # connection pool size
```

### Script Configuration
```bash
INVOKE_SCRIPT=                # path of an executable for firewall management (global fallback)
EXPIRE_SCRIPT=                # path of an executable for cleanup when Redis keys expire (global fallback)
INVOKE_ALWAYS=true            # execute INVOKE_SCRIPT every time an IP address is encountered (global fallback)
SYNC_SCRIPT_EXECUTION=true    # execute scripts synchronously to ensure firewall rules are created before DNS response (global fallback)
SCRIPT_CONFIG=                # path to JSON configuration file for per-client script settings
```

**📖 For detailed script configuration, see:** [docs/per-client-scripts.md](docs/per-client-scripts.md)

#### Script Execution Timing

dfirewall supports two execution modes for firewall scripts to ensure reliable application connectivity:

**Asynchronous Mode (Default):**
- DNS response sent immediately 
- Firewall scripts execute in background
- Faster DNS response times
- Risk: Client applications may fail to connect if they attempt connection before firewall rule exists

**Synchronous Mode (`SYNC_SCRIPT_EXECUTION=true`):**
- Firewall script executes first
- DNS response sent after script completes
- Slower DNS response times  
- Guarantee: Firewall rules exist before client receives DNS answer, ensuring reliable application connectivity

**Recommendation:** Use synchronous mode in production environments where application connection failures due to timing issues would impact service availability.

### Security Features Configuration
```bash
BLACKLIST_CONFIG=             # path to JSON configuration file for IP/domain blacklisting
REPUTATION_CONFIG=            # path to JSON configuration file for IP/domain reputation checking
AI_CONFIG=                    # path to JSON configuration file for AI-powered threat detection
CUSTOM_SCRIPT_CONFIG=         # path to JSON configuration file for user-provided pass/fail scripts
SNI_INSPECTION_CONFIG=        # path to JSON configuration file for SNI inspection and domain fronting detection
```

**📖 For detailed security configuration, see:**
- [docs/blacklist-configuration.md](docs/blacklist-configuration.md)
- [docs/reputation-checking.md](docs/reputation-checking.md)
- [docs/ai-threat-detection.md](docs/ai-threat-detection.md)
- [docs/sni-inspection.md](docs/sni-inspection.md)

### Web UI Configuration
```bash
WEB_UI_PORT=8080              # port for web-based rule management interface
```

### Web UI Authentication Configuration
```bash
WEBUI_AUTH_CONFIG=            # path to JSON configuration file for Web UI authentication settings
WEBUI_HTTPS_ENABLED=true      # enable HTTPS (true/false)
WEBUI_CERT_FILE=              # path to TLS certificate file for HTTPS
WEBUI_KEY_FILE=               # path to TLS private key file for HTTPS
WEBUI_PASSWORD_AUTH=true      # enable password authentication (true/false)
WEBUI_USERNAME=admin          # username for password authentication
WEBUI_PASSWORD=secret         # password for authentication (will be hashed automatically)
WEBUI_LDAP_AUTH=true          # enable LDAP authentication (true/false)
WEBUI_LDAP_SERVER=            # LDAP server hostname
WEBUI_LDAP_PORT=389           # LDAP server port (default: 389)
WEBUI_LDAP_BASE_DN=           # LDAP base DN for user search
WEBUI_LDAP_BIND_DN=           # LDAP bind DN for service account
WEBUI_LDAP_BIND_PASS=         # LDAP bind password for service account
WEBUI_LDAP_USER_ATTR=uid      # LDAP user attribute (default: uid)
WEBUI_LDAP_SEARCH_FILTER=     # LDAP search filter for users
WEBUI_HEADER_AUTH=true        # enable header-based authentication (true/false)
WEBUI_HEADER_NAME=            # HTTP header name to check for authentication
WEBUI_HEADER_VALUES=          # comma-separated list of valid header values
WEBUI_TRUSTED_PROXIES=        # comma-separated list of trusted proxy IPs/CIDRs
WEBUI_SESSION_SECRET=         # secret key for session signing (auto-generated if not provided)
WEBUI_SESSION_EXPIRY=24       # session expiry time in hours (default: 24)
```

**📖 For detailed Web UI authentication setup, see:** [docs/webui-authentication.md](docs/webui-authentication.md)

## Configuration Files

Many advanced features are configured through JSON configuration files referenced by environment variables:

### Script Configuration (`SCRIPT_CONFIG`)
Per-client script configuration for different firewall policies:
```json
{
  "clients": [
    {
      "pattern": "192.168.1.0/24",
      "type": "cidr",
      "invoke_script": "/scripts/home_network.sh",
      "expire_script": "/scripts/home_expire.sh",
      "invoke_always": false
    }
  ]
}
```

### Blacklist Configuration (`BLACKLIST_CONFIG`)
IP and domain blacklisting configuration:
```json
{
  "enabled": true,
  "redis_ip_key": "dfirewall:blacklist:ips",
  "redis_domain_key": "dfirewall:blacklist:domains",
  "ip_file": "/config/blacklist-ips.txt",
  "domain_file": "/config/blacklist-domains.txt"
}
```

### Reputation Configuration (`REPUTATION_CONFIG`)
Threat intelligence provider configuration:
```json
{
  "enabled": true,
  "min_threat_score": 0.7,
  "checkers": [
    {
      "name": "virustotal",
      "type": "both",
      "api_key": "your_api_key",
      "enabled": true
    }
  ]
}
```

### AI Configuration (`AI_CONFIG`)
AI-powered threat detection configuration:
```json
{
  "enabled": true,
  "provider": "openai",
  "api_key": "your_api_key",
  "model": "gpt-4",
  "domain_analysis": true,
  "traffic_anomalies": true
}
```

### Web UI Authentication (`WEBUI_AUTH_CONFIG`)
Web UI authentication configuration:
```json
{
  "https_enabled": true,
  "cert_file": "/path/to/cert.pem",
  "key_file": "/path/to/key.pem",
  "password_auth": {
    "enabled": true,
    "username": "admin",
    "password_hash": "$2a$10$..."
  },
  "ldap_auth": {
    "enabled": false,
    "server": "ldap.example.com",
    "port": 389
  }
}
```

### Upstream Configuration (`UPSTREAM_CONFIG`)
Advanced upstream DNS resolver routing configuration allows you to route DNS queries from different clients or for different domains to different upstream resolvers. This enables sophisticated DNS routing policies for network segmentation, geographic routing, or specialized DNS services.

#### Configuration Structure
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
      "client_pattern": "10.0.100.50",
      "upstream": "9.9.9.9:53",
      "description": "Specific client uses Quad9 DNS"
    },
    {
      "client_pattern": "^172\\.16\\..*",
      "upstream": "208.67.222.222:53",
      "description": "Docker network uses OpenDNS (regex pattern)"
    }
  ],
  "zone_configs": [
    {
      "zone_pattern": "*.internal.company.com",
      "upstream": "10.0.1.10:53",
      "description": "Internal company domains go to internal DNS"
    },
    {
      "zone_pattern": "example.com",
      "upstream": "8.8.4.4:53",
      "description": "Specific domain routing"
    },
    {
      "zone_pattern": "^.*\\.local$",
      "upstream": "127.0.0.1:5353",
      "description": ".local domains go to mDNS (regex pattern)"
    }
  ]
}
```

#### Configuration Fields

**Top Level:**
- `default_upstream`: Default upstream resolver when no specific rules match
- `client_configs`: Array of per-client routing rules (highest priority)
- `zone_configs`: Array of per-zone/domain routing rules (medium priority)

**Client Configuration:**
- `client_pattern`: Pattern to match client IPs
  - Exact IP: `"192.168.1.100"`
  - CIDR notation: `"192.168.1.0/24"`
  - Regex pattern: `"^10\\.0\\..*"` (escaped for JSON)
- `upstream`: Upstream DNS resolver for matching clients
- `description`: Optional description for documentation

**Zone Configuration:**
- `zone_pattern`: Pattern to match domains/zones
  - Exact domain: `"example.com"`
  - Wildcard: `"*.example.com"` (matches subdomains and the domain itself)
  - Regex pattern: `"^.*\\.local$"` (escaped for JSON)
- `upstream`: Upstream DNS resolver for matching zones
- `description`: Optional description for documentation

#### Routing Priority
Rules are evaluated in the following priority order:
1. **Client-specific rules** (highest priority) - matches client IP patterns
2. **Zone-specific rules** (medium priority) - matches domain patterns
3. **Default upstream** (lowest priority) - fallback when no rules match

#### Use Cases

**Network Segmentation:**
```json
{
  "default_upstream": "1.1.1.1:53",
  "client_configs": [
    {
      "client_pattern": "192.168.100.0/24",
      "upstream": "10.0.1.53:53",
      "description": "Management network uses internal DNS"
    },
    {
      "client_pattern": "192.168.200.0/24", 
      "upstream": "8.8.8.8:53",
      "description": "Guest network uses Google DNS"
    }
  ]
}
```

**Geographic DNS Routing:**
```json
{
  "default_upstream": "1.1.1.1:53",
  "zone_configs": [
    {
      "zone_pattern": "*.us.example.com",
      "upstream": "8.8.8.8:53",
      "description": "US domains via Google DNS"
    },
    {
      "zone_pattern": "*.eu.example.com",
      "upstream": "1.1.1.1:53",
      "description": "EU domains via Cloudflare DNS"
    }
  ]
}
```

**Split-Horizon DNS:**
```json
{
  "default_upstream": "8.8.8.8:53",
  "zone_configs": [
    {
      "zone_pattern": "*.internal.company.com",
      "upstream": "10.0.1.10:53",
      "description": "Internal domains via internal DNS"
    },
    {
      "zone_pattern": "*.local",
      "upstream": "127.0.0.1:5353",
      "description": "mDNS domains via local resolver"
    }
  ]
}
```

**Docker Container Routing:**
```json
{
  "default_upstream": "1.1.1.1:53",
  "client_configs": [
    {
      "client_pattern": "^172\\.17\\..*",
      "upstream": "127.0.0.11:53",
      "description": "Docker bridge network uses Docker's DNS"
    },
    {
      "client_pattern": "^172\\.18\\..*",
      "upstream": "8.8.8.8:53",
      "description": "Custom Docker network uses Google DNS"
    }
  ]
}
```

#### Pattern Matching

**IP Address Patterns:**
- **Exact Match**: `"192.168.1.100"` - matches only this IP
- **CIDR Notation**: `"192.168.1.0/24"` - matches entire subnet
- **Regex Pattern**: `"^10\\.0\\..*"` - matches any IP starting with 10.0.

**Domain Patterns:**
- **Exact Match**: `"example.com"` - matches only this domain
- **Wildcard**: `"*.example.com"` - matches subdomains and the domain itself
- **Regex Pattern**: `"^.*\\.local$"` - matches any domain ending with .local

#### Configuration Validation
```bash
# Test and validate configuration syntax
jq . /config/upstream-config.json
```

#### Integration with Environment Variables
```bash
# Set the configuration file path
UPSTREAM_CONFIG=/config/upstream-config.json

# The UPSTREAM environment variable becomes the fallback
# when no upstream_config is specified or no rules match
UPSTREAM=1.1.1.1:53

# Start dfirewall with upstream routing
docker-compose up
```

## Docker Deployment Configuration

### Docker Compose Example
```yaml
version: '3.8'
services:
  dfirewall:
    build: .
    network_mode: host
    cap_add:
      - NET_ADMIN
    environment:
      - UPSTREAM=1.1.1.1:53
      - REDIS=redis://127.0.0.1:6379
      - WEB_UI_PORT=8080
      - UPSTREAM_CONFIG=/config/upstream-config.json
      - TTL_GRACE_PERIOD_SECONDS=90
      - INVOKE_SCRIPT=/scripts/invoke_linux_ipset.sh
      - EXPIRE_SCRIPT=/scripts/expire_generic.sh
      - SYNC_SCRIPT_EXECUTION=true
      - DEBUG=true
    volumes:
      - ./config:/config
      - ./scripts:/scripts
    depends_on:
      - redis

  redis:
    image: redis:alpine
    network_mode: host
    volumes:
      - redis_data:/data

volumes:
  redis_data:
```

### Environment File (.env)
```bash
# Core configuration
UPSTREAM=1.1.1.1:53
REDIS=redis://127.0.0.1:6379
PORT=53
DEBUG=true

# Advanced upstream routing
UPSTREAM_CONFIG=/config/upstream-config.json
TTL_GRACE_PERIOD_SECONDS=90

# Scripts
INVOKE_SCRIPT=/scripts/invoke_linux_ipset.sh
EXPIRE_SCRIPT=/scripts/expire_generic.sh
SYNC_SCRIPT_EXECUTION=true

# Web UI
WEB_UI_PORT=8080
WEBUI_PASSWORD_AUTH=true
WEBUI_USERNAME=admin
WEBUI_PASSWORD=secure_password

# Security features
BLACKLIST_CONFIG=/config/blacklist-config.json
REPUTATION_CONFIG=/config/reputation-config.json
AI_CONFIG=/config/ai-config.json
```

## Configuration Validation

### Required Configuration Check
```bash
# Verify required environment variables are set
if [ -z "$UPSTREAM" ] || [ -z "$REDIS" ]; then
    echo "ERROR: UPSTREAM and REDIS environment variables are required"
    exit 1
fi
```

### Configuration Testing
```bash
# Test Redis connection
redis-cli -u $REDIS ping

# Test upstream DNS
dig @${UPSTREAM%:*} google.com

# Validate configuration files
jq . /config/blacklist-config.json
jq . /config/reputation-config.json
jq . /config/ai-config.json
```

### Health Check Endpoint
```bash
# Check configuration status via API
curl http://localhost:8080/api/config/status | jq .
```

## Security Considerations

### Environment Variable Security
- Store sensitive values (API keys, passwords) in secure environment variable management
- Use Docker secrets or Kubernetes secrets for container deployments
- Avoid logging sensitive environment variables
- Regularly rotate API keys and credentials

### Configuration File Security
- Restrict file permissions on configuration files (600 or 640)
- Store configuration files outside of web-accessible directories
- Use encrypted storage for sensitive configuration data
- Implement configuration backup and versioning

### Network Security
- Bind services to specific interfaces when possible
- Use TLS encryption for Redis connections in production
- Implement proper firewall rules for dfirewall components
- Monitor configuration changes and access

## Troubleshooting Configuration

### Common Issues

#### Environment Variables Not Set
```bash
# Check environment variables
env | grep -E '(UPSTREAM|REDIS|PORT)'

# Verify Docker environment
docker exec dfirewall env | grep UPSTREAM
```

#### Configuration File Errors
```bash
# Validate JSON syntax
jsonlint /config/blacklist-config.json

# Check file permissions
ls -la /config/

# Verify file accessibility from container
docker exec dfirewall cat /config/blacklist-config.json
```

#### Redis Connection Issues
```bash
# Test Redis connectivity
redis-cli -u $REDIS ping

# Check Redis logs
docker logs redis

# Verify Redis authentication
redis-cli -u $REDIS auth $REDIS_PASSWORD
```

### Debug Mode
Enable debug logging to troubleshoot configuration issues:
```bash
DEBUG=true docker-compose up
```

This will provide detailed logging of configuration loading and validation.

## Configuration Best Practices

1. **Use Configuration Management**: Implement version control for configuration files
2. **Environment Separation**: Use different configurations for development, staging, and production
3. **Security First**: Store sensitive data securely and rotate credentials regularly
4. **Validation**: Always validate configuration changes before deployment
5. **Monitoring**: Monitor configuration changes and their impact on system behavior
6. **Documentation**: Keep configuration documentation up to date
7. **Backup**: Maintain backups of working configurations
8. **Testing**: Test configuration changes in non-production environments first
