# SSH Log Monitoring

The SSH log monitoring feature allows dfirewall to connect to remote servers via SSH and monitor log files for IP addresses and domains. This extends the firewall's capability beyond just DNS interception to include detection from various log sources.

## Features

- **SSH Connection Management**: Supports password, key-based, and SSH agent authentication
- **Log File Tailing**: Real-time monitoring with log rotation handling
- **Pattern Extraction**: Configurable regex patterns for extracting IPs and domains from log lines
- **Redis Integration**: Extracted IPs/domains are stored in Redis with TTL expiration
- **Firewall Integration**: Integrates with existing script execution system for dynamic firewall rules
- **Web UI Integration**: Status monitoring via the web interface
- **Resilient Connections**: Automatic reconnection with exponential backoff

## Configuration

SSH log monitoring is configured via the `SSH_LOG_CONFIG` environment variable pointing to a JSON configuration file.

### Environment Variable

```bash
export SSH_LOG_CONFIG="/path/to/ssh_log_config.json"
```

### Configuration Structure

```json
{
  "enabled": true,
  "global_defaults": {
    "port": 22,
    "connection_timeout": 30,
    "keep_alive": 30,
    "max_retries": 3,
    "auth_method": "key",
    "buffer_size": 4096,
    "max_line_length": 1024,
    "process_interval": 1,
    "default_ttl": 3600,
    "strict_host_key_checking": false
  },
  "retry_config": {
    "initial_delay": 5,
    "max_delay": 300,
    "backoff_multiplier": 2.0,
    "max_reconnect_attempts": 10,
    "reconnect_interval": 60,
    "health_check_interval": 300
  },
  "servers": [...]
}
```

### Server Configuration

Each server configuration includes:

- **Connection Details**: host, port, username
- **Authentication**: method (password/key/agent), credentials
- **Host Validation**: strict checking, known hosts, fingerprints
- **Log Files**: list of log files to monitor

```json
{
  "name": "web-server-1",
  "host": "192.168.1.100",
  "port": 22,
  "username": "dfirewall",
  "auth_method": "key",
  "private_key_path": "/home/dfirewall/.ssh/id_rsa",
  "strict_host_key_checking": false,
  "enabled": true,
  "log_files": [...]
}
```

### Log File Configuration

Each log file configuration specifies:

- **Path**: Full path to log file on remote server
- **Patterns**: Regex patterns for extracting IPs and domains
- **Handling**: Rotation following, buffering, filtering
- **Integration**: How to treat extracted data for firewall rules

```json
{
  "path": "/var/log/nginx/access.log",
  "description": "Nginx access log - extract client IPs",
  "ip_regex": "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})",
  "domain_regex": "Host:\\s*([a-zA-Z0-9.-]+)",
  "follow_rotation": true,
  "start_from_end": true,
  "treat_as_client": true,
  "default_ttl": 3600,
  "enabled": true
}
```

## Authentication Methods

### Password Authentication

```json
{
  "auth_method": "password",
  "password": "your_secure_password"
}
```

### Key-based Authentication

From file:
```json
{
  "auth_method": "key",
  "private_key_path": "/path/to/private/key",
  "passphrase": "optional_passphrase"
}
```

Inline key data:
```json
{
  "auth_method": "key",
  "private_key_data": "LS0tLS1CRUdJTi...",
  "passphrase": "optional_passphrase"
}
```

### SSH Agent Authentication

```json
{
  "auth_method": "agent"
}
```

*Note: SSH agent authentication is planned but not yet implemented.*

## Host Key Verification

### Disable Verification (Development)

```json
{
  "strict_host_key_checking": false
}
```

### Known Hosts File

```json
{
  "strict_host_key_checking": true,
  "known_hosts_file": "/home/dfirewall/.ssh/known_hosts"
}
```

### Fingerprint Verification

```json
{
  "strict_host_key_checking": true,
  "host_key_fingerprint": "SHA256:..."
}
```

## Regex Pattern Examples

### IP Address Extraction

```json
{
  "ip_regex": "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
}
```

### Domain Extraction

```json
{
  "domain_regex": "Host:\\s*([a-zA-Z0-9.-]+)"
}
```

### Log Filtering

Include only HTTP requests:
```json
{
  "include_filter": "\\s(GET|POST|PUT|DELETE)\\s"
}
```

Exclude local network traffic:
```json
{
  "exclude_filter": "SRC=192\\.168\\."
}
```

## Common Use Cases

### Web Server Access Logs

Monitor Nginx/Apache access logs to extract client IPs and requested domains for firewall rules.

### Firewall Logs

Monitor iptables logs to track blocked destination IPs and create temporary allow rules.

### DNS Server Logs

Monitor BIND query logs to extract DNS queries and client IPs.

### Application Logs

Monitor custom application logs with regex patterns specific to your log format.

## Integration with dfirewall

Extracted IPs and domains are integrated with dfirewall's existing systems:

1. **Redis Storage**: Rules stored with TTL expiration
2. **Script Execution**: Existing script system for firewall management
3. **Blacklist Checking**: Extracted IPs/domains checked against blacklists
4. **Reputation Checking**: Integration with threat intelligence
5. **AI Analysis**: Optional AI-powered threat detection

## API Endpoints

### Get SSH Monitoring Status

```bash
curl -X GET http://localhost:8080/api/ssh/status
```

Returns status of all SSH connections and log monitoring activities.

### Configuration Status

```bash
curl -X GET http://localhost:8080/api/config/status
```

Returns current SSH log configuration along with other system configurations.

## Security Considerations

- Store SSH credentials securely
- Use key-based authentication when possible
- Enable host key checking in production
- Limit log file access permissions on remote servers
- Monitor for connection anomalies
- Use strong patterns to avoid false positives

## Troubleshooting

### Connection Issues

- Check SSH connectivity: `ssh username@hostname`
- Verify credentials and authentication method
- Check firewall rules between dfirewall and remote servers
- Review SSH server logs on remote systems

### Pattern Matching Issues

- Test regex patterns with sample log lines
- Use DEBUG=1 environment variable for verbose logging
- Check include/exclude filters
- Verify log file permissions and accessibility

### Performance Issues

- Adjust buffer sizes and processing intervals
- Limit line length processing
- Use specific include filters to reduce processing
- Monitor connection and processing statistics via API

## Example Configurations

See `examples/ssh_log_config.json` for complete configuration examples including:

- Web server access log monitoring
- Firewall log analysis
- DNS server query monitoring
- Custom application log parsing