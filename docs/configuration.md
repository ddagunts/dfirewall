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
SCRIPT_CONFIG=                # path to JSON configuration file for per-client script settings
```

**📖 For detailed script configuration, see:** [docs/per-client-scripts.md](docs/per-client-scripts.md)

### Security Features Configuration
```bash
BLACKLIST_CONFIG=             # path to JSON configuration file for IP/domain blacklisting
REPUTATION_CONFIG=            # path to JSON configuration file for IP/domain reputation checking
AI_CONFIG=                    # path to JSON configuration file for AI-powered threat detection
CUSTOM_SCRIPT_CONFIG=         # path to JSON configuration file for user-provided pass/fail scripts
```

**📖 For detailed security configuration, see:**
- [docs/blacklist-configuration.md](docs/blacklist-configuration.md)
- [docs/reputation-checking.md](docs/reputation-checking.md)
- [docs/ai-threat-detection.md](docs/ai-threat-detection.md)

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
      - INVOKE_SCRIPT=/scripts/invoke_linux_ipset.sh
      - EXPIRE_SCRIPT=/scripts/expire_generic.sh
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

# Scripts
INVOKE_SCRIPT=/scripts/invoke_linux_ipset.sh
EXPIRE_SCRIPT=/scripts/expire_generic.sh

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
