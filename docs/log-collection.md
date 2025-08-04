# Log Collection and Analysis

dfirewall can collect and analyze logs from remote and local sources to extract IP addresses and domains for firewall rule creation. This feature enables proactive security by monitoring various log sources and automatically adding discovered threats to the firewall.

## Overview

The log collection system monitors log files in real-time, extracts IP addresses and domains using configurable regex patterns, and processes them through the security pipeline (blacklist checking, reputation analysis, AI threat detection, and custom scripts) before creating firewall rules.

## Configuration

Enable log collection by setting the `LOG_COLLECTOR_CONFIG` environment variable:

```bash
LOG_COLLECTOR_CONFIG=/path/to/log-collector-config.json
```

### Configuration File Structure

The configuration file supports the following top-level settings:

```json
{
  "enabled": true,
  "default_ttl": 3600,
  "buffer_size": 65536,
  "connect_timeout": 30,
  "read_timeout": 60,
  "reconnect_delay": 10,
  "max_reconnects": -1,
  "sources": [...]
}
```

#### Global Settings

- `enabled` (boolean): Enable/disable log collection globally
- `default_ttl` (integer): Default TTL for firewall rules created from log entries (seconds)
- `buffer_size` (integer): Buffer size for reading log files (bytes)
- `connect_timeout` (integer): SSH connection timeout (seconds)
- `read_timeout` (integer): Read timeout for log files (seconds)
- `reconnect_delay` (integer): Delay between reconnection attempts (seconds)
- `max_reconnects` (integer): Maximum reconnection attempts (-1 for unlimited)

## Log Sources

The system supports two types of log sources:

### Local File Monitoring

Monitor local log files for changes:

```json
{
  "name": "nginx-access",
  "type": "local",
  "file_path": "/var/log/nginx/access.log",
  "follow_rotation": true,
  "start_from_end": true,
  "enabled": true,
  "ttl": 3600,
  "patterns": [...]
}
```

### Remote SSH Log Collection

Collect logs from remote servers via SSH:

```json
{
  "name": "apache-access",
  "type": "ssh",
  "host": "webserver.example.com",
  "port": 22,
  "username": "loguser",
  "auth_method": "key",
  "private_key_path": "/home/dfirewall/.ssh/id_rsa",
  "file_path": "/var/log/apache2/access.log",
  "follow_rotation": true,
  "start_from_end": true,
  "ttl": 7200,
  "enabled": true,
  "patterns": [...]
}
```

#### SSH Authentication Methods

**Key-based authentication:**
```json
{
  "auth_method": "key",
  "private_key_path": "/path/to/private/key"
}
```

**Password authentication:**
```json
{
  "auth_method": "password",
  "password": "your_password"
}
```

**Key with passphrase and password fallback:**
```json
{
  "auth_method": "key_password",
  "private_key_path": "/path/to/key",
  "passphrase": "key_passphrase",
  "password": "fallback_password"
}
```

#### Source Configuration Options

- `name` (string): Unique identifier for the log source
- `type` (string): "local" or "ssh"
- `file_path` (string): Path to the log file
- `follow_rotation` (boolean): Follow log rotation (recommended: true)
- `start_from_end` (boolean): Start reading from end of file (true) or beginning (false)
- `enabled` (boolean): Enable/disable this source
- `ttl` (integer): TTL override for rules from this source (optional)
- `environment` (object): Environment variables for script execution (optional)

**SSH-specific options:**
- `host` (string): Remote server hostname/IP
- `port` (integer): SSH port (default: 22)
- `username` (string): SSH username
- `auth_method` (string): Authentication method
- `private_key_path` (string): Path to SSH private key
- `passphrase` (string): Private key passphrase (if needed)
- `password` (string): SSH password or fallback password

## Pattern Matching

Each log source can have multiple regex patterns to extract different types of data:

```json
{
  "patterns": [
    {
      "name": "nginx-access-ip",
      "regex": "^([0-9\\.]+) - - \\[.*?\\] \".*?\" \\d+ \\d+ \".*?\" \".*?\"",
      "type": "ip",
      "ip_group": 1,
      "enabled": true,
      "test_string": "192.168.1.100 - - [04/Aug/2025:10:15:30 +0000] \"GET /api/status HTTP/1.1\" 200 1234 \"-\" \"curl/7.68.0\""
    }
  ]
}
```

### Pattern Types

**IP extraction only:**
```json
{
  "type": "ip",
  "ip_group": 1
}
```

**Domain extraction only:**
```json
{
  "type": "domain",
  "domain_group": 1
}
```

**Both IP and domain extraction:**
```json
{
  "type": "both",
  "ip_group": 1,
  "domain_group": 2,
  "client_ip_group": 3
}
```

#### Pattern Configuration Options

- `name` (string): Unique pattern identifier
- `regex` (string): Regular expression with capture groups
- `type` (string): "ip", "domain", or "both"
- `ip_group` (integer): Regex group number for IP address
- `domain_group` (integer): Regex group number for domain
- `client_ip_group` (integer): Regex group number for client IP (optional)
- `enabled` (boolean): Enable/disable this pattern
- `test_string` (string): Test string for validation (optional but recommended)

## Example Configurations

### Web Server Access Logs

**Nginx Access Log:**
```json
{
  "name": "nginx-access",
  "type": "local",
  "file_path": "/var/log/nginx/access.log",
  "follow_rotation": true,
  "start_from_end": true,
  "enabled": true,
  "patterns": [
    {
      "name": "client-ip",
      "regex": "^([0-9\\.]+) - - \\[.*?\\] \".*?\" \\d+ \\d+",
      "type": "ip",
      "ip_group": 1,
      "enabled": true
    }
  ]
}
```

**Apache Access Log:**
```json
{
  "name": "apache-access",
  "type": "ssh",
  "host": "webserver.example.com",
  "port": 22,
  "username": "loguser",
  "auth_method": "key",
  "private_key_path": "/home/dfirewall/.ssh/id_rsa",
  "file_path": "/var/log/apache2/access.log",
  "patterns": [
    {
      "name": "client-ip",
      "regex": "^([0-9\\.]+) - - \\[.*?\\] \".*?\" \\d+ \\d+",
      "type": "ip",
      "ip_group": 1,
      "enabled": true
    }
  ]
}
```

### Firewall Logs

```json
{
  "name": "firewall-logs",
  "type": "ssh",
  "host": "firewall.example.com",
  "port": 22,
  "username": "admin",
  "auth_method": "key",
  "private_key_path": "/home/dfirewall/.ssh/firewall_key",
  "file_path": "/var/log/firewall.log",
  "patterns": [
    {
      "name": "blocked-connections",
      "regex": "BLOCKED: ([0-9\\.]+) -> ([0-9\\.]+)",
      "type": "both",
      "ip_group": 1,
      "client_ip_group": 2,
      "enabled": true
    }
  ]
}
```

### Application Logs

```json
{
  "name": "application-logs",
  "type": "local",
  "file_path": "/var/log/myapp/connections.log",
  "patterns": [
    {
      "name": "outbound-connections",
      "regex": "Connecting to ([a-zA-Z0-9.-]+) \\(([0-9\\.]+)\\)",
      "type": "both",
      "domain_group": 1,
      "ip_group": 2,
      "enabled": true
    }
  ]
}
```

### Proxy Logs (Squid)

```json
{
  "name": "squid-proxy",
  "type": "ssh",
  "host": "proxy.example.com",
  "port": 22,
  "username": "logcollector",
  "auth_method": "key",
  "private_key_path": "/home/dfirewall/.ssh/proxy_key",
  "file_path": "/var/log/squid/access.log",
  "patterns": [
    {
      "name": "proxy-access",
      "regex": "^\\d+\\.\\d+ +\\d+ ([0-9\\.]+) \\w+/\\d+ \\d+ \\w+ (https?://[^/]+)",
      "type": "both",
      "client_ip_group": 1,
      "domain_group": 2,
      "enabled": true
    }
  ]
}
```

## Security Pipeline Integration

Extracted IP addresses and domains automatically flow through dfirewall's security pipeline:

1. **Blacklist Check**: Verify against configured blacklists
2. **Reputation Check**: Query threat intelligence providers (VirusTotal, AbuseIPDB, etc.)
3. **AI Analysis**: Analyze with configured AI providers (OpenAI, Claude, local models)
4. **Custom Scripts**: Run user-defined validation scripts
5. **Firewall Rules**: Create rules for validated threats

## Testing and Validation

### Pattern Testing

Use the `test_string` field in pattern configurations to validate regex patterns:

```bash
# Test configuration file patterns
go run . -validate-patterns /path/to/log-collector-config.json
```

### Configuration Testing

```bash
# Test entire configuration file
go run . -config-test /path/to/log-collector-config.json
```

## Monitoring and Statistics

Log collector statistics are stored in Redis with keys like:
- `logcollector:stats:source_name:processed`
- `logcollector:stats:source_name:errors`
- `logcollector:stats:source_name:matches`

These can be viewed through the Web UI or accessed directly via Redis.

## Troubleshooting

### Common Issues

**SSH Connection Failures:**
- Verify SSH credentials and connectivity
- Check firewall rules between dfirewall and remote hosts
- Ensure SSH key permissions are correct (600 for private keys)

**Pattern Matching Issues:**
- Use the `test_string` field to validate regex patterns
- Run pattern validation with `-validate-patterns`
- Check logs for regex compilation errors

**Performance Issues:**
- Adjust `buffer_size` for large log files
- Consider `start_from_end: true` for active logs
- Monitor Redis memory usage with many log sources

**File Rotation Issues:**
- Ensure `follow_rotation: true` is set
- Verify log rotation configuration doesn't break file handles
- Monitor reconnection behavior in logs

### Debug Mode

Enable debug logging to troubleshoot log collection issues:

```bash
DEBUG=1 LOG_COLLECTOR_CONFIG=/path/to/config.json ./dfirewall
```

## Security Considerations

- Store SSH private keys securely with appropriate file permissions (600)
- Use dedicated SSH users with minimal privileges for log collection
- Consider using SSH key passphrases for additional security
- Regularly rotate SSH keys and passwords
- Monitor log collection access patterns for anomalies
- Ensure log sources don't contain sensitive information in extracted patterns

## Example Complete Configuration

See [config/log-collector-config.example.json](../config/log-collector-config.example.json) for a comprehensive example configuration with multiple source types and pattern examples.