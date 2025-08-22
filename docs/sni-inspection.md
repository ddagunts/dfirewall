# SNI Inspection

SNI (Server Name Indication) inspection is an advanced security feature in dfirewall that helps detect TLS connection abuse where clients resolve one domain via DNS but then connect with a different domain in the TLS SNI header.

## Overview

The SNI inspection feature works by:

1. **DNS Response Modification**: When enabled for a client or domain, dfirewall responds to DNS queries with a configurable proxy IP instead of the real resolved IP
2. **TLS Interception**: dfirewall listens on configurable ports to intercept incoming TLS connections
3. **SNI Validation**: It inspects the TLS ClientHello SNI header and compares it to the originally requested domain
4. **Security Actions**: Depending on configuration, it can log mismatches, block connections, or proxy valid connections

## Use Cases

### Security Threat Detection

SNI inspection helps detect several attack scenarios:

- **DNS Cache Poisoning**: Attackers poison DNS to redirect legitimate domains to malicious IPs, then use the original legitimate domain in SNI
- **Domain Fronting**: Clients resolve a legitimate domain but connect to a different (potentially malicious) service using SNI
- **Certificate Abuse**: Clients obtain firewall rules for one domain but abuse them to connect to different services

### Example Attack Scenario

1. Client requests DNS for `www.google.com`
2. Attacker returns malicious IP `1.2.3.4` instead of Google's real IP
3. Client connects to `1.2.3.4` but uses SNI header `gmail.com`
4. Without SNI inspection, firewall allows connection thinking it's to Google
5. With SNI inspection enabled, dfirewall detects the mismatch and blocks/logs the connection

## Configuration

### Environment Variables

```bash
export SNI_INSPECTION_CONFIG="/path/to/sni-inspection-config.json"
```

### Configuration File Structure

```json
{
  "enabled": true,
  "proxy_ips": ["10.0.1.100"],
  "proxy_ports": [8443, 9443],
  
  "client_configs": [
    {
      "client_pattern": "192.168.1.0/24",
      "enabled": true,
      "proxy_ip": "10.0.1.100"
    }
  ],
  
  "domain_configs": [
    {
      "domain_pattern": "*.banking.com",
      "enabled": true
    }
  ],
  
  "strict_validation": true,
  "log_only": false
}
```

### Configuration Options

#### Global Settings

- **enabled**: Enable/disable SNI inspection globally
- **proxy_ips**: List of IP addresses to return in DNS responses instead of real IPs
- **proxy_ports**: Ports to listen on for TLS connection interception
- **cert_file/key_file**: TLS certificate for the proxy server (optional)

#### Connection Settings

- **connection_timeout**: Connection timeout in seconds (default: 30)
- **handshake_timeout**: TLS handshake timeout in seconds (default: 10)
- **idle_timeout**: Idle connection timeout in seconds (default: 300)
- **max_connections**: Maximum concurrent connections (default: 1000)

#### Validation Settings

- **strict_validation**: Block connections with SNI mismatches (default: true)
- **log_only**: Only log mismatches, don't block connections (default: false)

#### Client-Specific Configuration

Configure SNI inspection on a per-client basis:

```json
"client_configs": [
  {
    "client_pattern": "192.168.1.0/24",
    "enabled": true,
    "proxy_ip": "10.0.1.100",
    "description": "Enable for internal network"
  },
  {
    "client_pattern": "regex:^172\\.16\\..*",
    "enabled": false,
    "description": "Disable for Docker network"
  }
]
```

**Pattern Types**:
- **Exact IP**: `192.168.1.100`
- **CIDR notation**: `192.168.1.0/24`
- **Regex patterns**: `regex:^172\\.16\\..*`

#### Domain-Specific Configuration

Configure SNI inspection on a per-domain basis:

```json
"domain_configs": [
  {
    "domain_pattern": "*.banking.com",
    "enabled": true,
    "proxy_ip": "10.0.1.101",
    "description": "High-security domains"
  },
  {
    "domain_pattern": "regex:^.*\\.internal\\..*$",
    "enabled": false,
    "description": "Skip internal domains"
  }
]
```

**Pattern Types**:
- **Exact domain**: `example.com`
- **Wildcard**: `*.example.com` (matches subdomains and exact domain)
- **Regex patterns**: `regex:^.*\\.suspicious\\..*$`

### Configuration Priority

1. **Client-specific rules** (highest priority)
2. **Domain-specific rules** (medium priority)
3. **Global settings** (lowest priority)

## Deployment

### Docker Compose Integration

Add to your `docker-compose.yml`:

```yaml
services:
  dfirewall:
    environment:
      - SNI_INSPECTION_CONFIG=/config/sni-inspection-config.json
    volumes:
      - ./config/sni-inspection-config.json:/config/sni-inspection-config.json:ro
      - ./tls:/etc/dfirewall/tls:ro
    # Host networking required for proxy port access
    network_mode: host
```

### TLS Certificates

If using TLS termination at the proxy:

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout proxy.key -out proxy.crt -days 365 -nodes

# Or use Let's Encrypt for production
certbot certonly --standalone -d proxy.yourdomain.com
```

### Network Configuration

Ensure proxy ports are accessible:

```bash
# Allow SNI proxy ports through firewall
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -p tcp --dport 9443 -j ACCEPT
```

## Monitoring and Management

### API Endpoints

- **GET /api/sni/stats**: Get SNI inspection statistics
- **GET /api/sni/connections**: List active SNI connections
- **GET /api/sni/config**: View current SNI configuration
- **POST /api/sni/validate**: Validate a specific client/domain/SNI combination

### Statistics

View comprehensive statistics via the API:

```json
{
  "total_connections": 1250,
  "valid_connections": 1180,
  "invalid_connections": 70,
  "blocked_connections": 65,
  "active_connections": 15,
  "client_stats": {
    "192.168.1.50": {
      "total_connections": 45,
      "valid_connections": 44,
      "invalid_connections": 1
    }
  },
  "domain_stats": {
    "example.com": {
      "total_connections": 120,
      "valid_connections": 115,
      "invalid_connections": 5
    }
  }
}
```

### Logging

SNI inspection events are logged with clear identifiers:

```
SNI inspection: client 192.168.1.50 querying example.com, returning proxy IP 10.0.1.100 instead of 1.2.3.4
SNI MISMATCH LOG: 192.168.1.50 requested example.com but connected with SNI evil.com (connection: abc123)
SNI BLOCK: Connection abc123 blocked due to SNI mismatch (requested: example.com, sni: evil.com)
```

## Security Considerations

### Proxy IP Selection

- Use dedicated IP addresses for proxy functionality
- Ensure proxy IPs don't conflict with legitimate services
- Consider using internal/private IP ranges when possible

### Performance Impact

- SNI inspection adds latency to TLS connections
- Monitor proxy server resource usage
- Scale proxy capacity based on connection volume

### Certificate Management

- Use proper TLS certificates for the proxy server
- Implement certificate rotation procedures
- Monitor certificate expiration

### False Positives

- Legitimate CDN usage may trigger SNI mismatches
- Monitor and whitelist known legitimate patterns
- Use `log_only` mode initially to assess impact

## Troubleshooting

### Common Issues

**SNI inspection not working**:
- Check that `SNI_INSPECTION_CONFIG` environment variable is set
- Verify configuration file JSON syntax
- Ensure proxy ports are not blocked by firewall

**High false positive rate**:
- Review client and domain patterns for overly broad matching
- Enable `log_only` mode to analyze traffic patterns
- Consider excluding CDN domains or legitimate subdomains

**Performance issues**:
- Increase `max_connections` if seeing connection limits
- Adjust timeout values based on network conditions
- Monitor proxy server resource usage

### Debug Logging

Enable debug logging for detailed SNI inspection information:

```bash
DEBUG=1 ./dfirewall
```

This provides detailed logs of:
- SNI inspection decisions
- TLS handshake parsing
- Connection proxying details
- Validation logic execution

## Example Configurations

### High-Security Environment

```json
{
  "enabled": true,
  "proxy_ips": ["10.0.1.100"],
  "proxy_ports": [8443],
  "strict_validation": true,
  "log_only": false,
  "client_configs": [
    {
      "client_pattern": "0.0.0.0/0",
      "enabled": true,
      "description": "Enable for all clients"
    }
  ]
}
```

### Banking/Financial Services

```json
{
  "enabled": true,
  "proxy_ips": ["10.0.1.100", "10.0.1.101"],
  "proxy_ports": [8443, 9443],
  "strict_validation": true,
  "log_only": false,
  "domain_configs": [
    {
      "domain_pattern": "*.bank.com",
      "enabled": true,
      "proxy_ip": "10.0.1.100"
    },
    {
      "domain_pattern": "*.financial.org",
      "enabled": true,
      "proxy_ip": "10.0.1.101"
    }
  ]
}
```

### Development Environment

```json
{
  "enabled": true,
  "proxy_ips": ["10.0.1.100"],
  "proxy_ports": [8443],
  "strict_validation": false,
  "log_only": true,
  "client_configs": [
    {
      "client_pattern": "192.168.1.0/24",
      "enabled": true,
      "description": "Monitor development network"
    }
  ]
}
```

## Integration with Other Features

### Blacklisting

SNI inspection works alongside existing blacklisting:
- Domain blacklist checks happen before SNI inspection
- IP blacklist checks apply to original resolved IPs, not proxy IPs
- Blacklisted domains won't trigger SNI inspection

### Reputation Checking

- Reputation checks apply to original IPs/domains before proxy modification
- SNI inspection adds an additional layer after reputation validation
- Both systems can independently block or log threats

### AI Analysis

- AI analysis can process SNI mismatch patterns
- Machine learning can identify anomalous SNI usage
- AI can provide context for SNI-based threat detection

### Custom Scripts

- Custom validation scripts receive original resolved IPs
- Scripts can implement additional SNI-based validation logic
- Results integrate with SNI inspection decisions