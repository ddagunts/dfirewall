# Blacklist Configuration

This document provides comprehensive guidance for configuring IP and domain blacklisting in dfirewall.

## Overview

dfirewall supports comprehensive blacklisting capabilities for both IP addresses and domain names. Blacklists can be configured through static files, dynamic Redis storage, or a combination of both methods. This enables blocking of known malicious IPs and domains before they can establish connections.

## Configuration Methods

### 1. JSON Configuration File

Create a blacklist configuration file and set `BLACKLIST_CONFIG=/path/to/blacklist.json`:

```json
{
  "enabled": true,
  "ip_blacklist": [
    "192.168.100.5",
    "10.0.0.0/8",
    "172.16.0.0/12"
  ],
  "domain_blacklist": [
    "malware.example.com",
    "*.phishing.com",
    "badactor.org"
  ],
  "ip_blacklist_file": "/etc/dfirewall/blocked_ips.txt",
  "domain_blacklist_file": "/etc/dfirewall/blocked_domains.txt",
  "use_redis_blacklist": true,
  "redis_ip_key": "dfirewall:blacklist:ips",
  "redis_domain_key": "dfirewall:blacklist:domains",
  "use_regex": true,
  "case_sensitive": false,
  "refresh_interval": 300,
  "log_only": false,
  "block_on_match": true
}
```

### 2. File-Based Blacklists

#### IP Blacklist File Format
Create `/etc/dfirewall/blocked_ips.txt`:
```
# IP Blacklist - one entry per line
# Comments start with #
192.168.100.5
10.0.0.0/8
172.16.0.0/12
203.0.113.0/24
2001:db8::/32
```

#### Domain Blacklist File Format
Create `/etc/dfirewall/blocked_domains.txt`:
```
# Domain Blacklist - one entry per line
# Comments start with #
malware.example.com
*.phishing.com      # Wildcard patterns supported 
badactor.org
^evil.*\.com$       # Regex patterns supported
suspicious-site.net
```

### 3. Redis-Based Dynamic Blacklists

#### Add IPs to Redis Blacklist
```bash
# Add single IP
redis-cli SADD dfirewall:blacklist:ips "192.168.100.5"

# Add CIDR range
redis-cli SADD dfirewall:blacklist:ips "10.0.0.0/8"

# Add multiple IPs
redis-cli SADD dfirewall:blacklist:ips "1.2.3.4" "5.6.7.8" "9.10.11.12"
```

#### Add Domains to Redis Blacklist
```bash
# Add single domain
redis-cli SADD dfirewall:blacklist:domains "malware.example.com"

# Add wildcard domain (blocks all subdomains)
redis-cli SADD dfirewall:blacklist:domains "*.phishing.com"

# Add regex pattern
redis-cli SADD dfirewall:blacklist:domains "^evil.*\.com$"

# Add multiple domains with different patterns
redis-cli SADD dfirewall:blacklist:domains "bad1.com" "*.bad2.org" "^malicious.*\.net$"
```

## Configuration Options

### Core Settings
- **`enabled`**: Enable/disable blacklist functionality globally
- **`block_on_match`**: Block traffic when blacklist matches (true) or just log (false)
- **`log_only`**: Log blacklist matches without blocking (overrides block_on_match)

### Static Blacklists
- **`ip_blacklist`**: Array of IPs/CIDRs to block in configuration
- **`domain_blacklist`**: Array of domains/patterns to block in configuration
- **`ip_blacklist_file`**: Path to file containing IP blacklist entries
- **`domain_blacklist_file`**: Path to file containing domain blacklist entries

### Dynamic Redis Blacklists
- **`use_redis_blacklist`**: Enable Redis-based dynamic blacklists
- **`redis_ip_key`**: Redis key name for IP blacklist set
- **`redis_domain_key`**: Redis key name for domain blacklist set

### Pattern Matching
- **`use_regex`**: Enable regex pattern matching for domains
- **`case_sensitive`**: Case-sensitive domain matching

### Performance Settings
- **`refresh_interval`**: Seconds between file-based blacklist refreshes

## Recent Security Improvements

### 🆕 Enhanced Domain Pattern Matching
Recent security improvements have significantly enhanced domain blacklist functionality:

- **Wildcard Pattern Support**: Both Redis and file-based blacklists now support wildcard patterns like `*.evil.com`
- **Consistent Parent Domain Blocking**: Adding `evil.com` to any blacklist now blocks `www.evil.com`, `api.evil.com`, etc.
- **CNAME Bypass Prevention**: Fixed vulnerability where domains with CNAME records could bypass blacklists
- **Unified Pattern Matching**: Consistent wildcard and regex support across all blacklist types

### Pattern Support Matrix
| Pattern Type | File Blacklist | Redis Blacklist | Example |
|-------------|---------------|-----------------|---------|
| Exact Match | ✅ | ✅ | `evil.com` |
| Parent Domain | ✅ | ✅ | `evil.com` blocks `www.evil.com` |
| Wildcard | ✅ | ✅ | `*.evil.com` |
| Regex | ✅ | ✅ | `^evil.*\.com$` |

## Blacklist Types and Patterns

### IP Address Blacklisting

#### Single IP Addresses
```json
{
  "ip_blacklist": [
    "192.168.1.100",
    "10.0.0.50", 
    "203.0.113.15"
  ]
}
```

#### CIDR Network Ranges
```json
{
  "ip_blacklist": [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "203.0.113.0/24"
  ]
}
```

#### IPv6 Support
```json
{
  "ip_blacklist": [
    "2001:db8::1",
    "2001:db8::/32",
    "fe80::/10"
  ]
}
```

### Domain Name Blacklisting

#### Exact Domain Matching
```json
{
  "domain_blacklist": [
    "malware.example.com",
    "phishing.badsite.org",
    "suspicious.net"
  ]
}
```

#### Wildcard Domain Matching
```json
{
  "domain_blacklist": [
    "*.malware.com",
    "*.phishing.*",
    "bad*.example.org"
  ]
}
```

#### Regex Pattern Matching
```json
{
  "use_regex": true,
  "domain_blacklist": [
    ".*\\.malware\\..*",
    "^phishing-.*\\.com$",
    ".*-suspicious\\..*"
  ]
}
```

## Advanced Configuration Examples

### Corporate Security Setup
```json
{
  "enabled": true,
  "ip_blacklist_file": "/etc/dfirewall/corporate_blocked_ips.txt",
  "domain_blacklist_file": "/etc/dfirewall/corporate_blocked_domains.txt",
  "use_redis_blacklist": true,
  "redis_ip_key": "corporate:security:blocked_ips",
  "redis_domain_key": "corporate:security:blocked_domains",
  "use_regex": true,
  "case_sensitive": false,
  "refresh_interval": 60,
  "block_on_match": true,
  "log_only": false
}
```

### High-Security Environment
```json
{
  "enabled": true,
  "ip_blacklist": [
    "0.0.0.0/8",
    "127.0.0.0/8", 
    "169.254.0.0/16",
    "224.0.0.0/4"
  ],
  "domain_blacklist": [
    "*.onion",
    "*.bit",
    "*.i2p"
  ],
  "ip_blacklist_file": "/etc/dfirewall/threat_intelligence_ips.txt",
  "domain_blacklist_file": "/etc/dfirewall/threat_intelligence_domains.txt",
  "use_redis_blacklist": true,
  "use_regex": true,
  "refresh_interval": 30,
  "block_on_match": true
}
```

### Development/Testing Environment
```json
{
  "enabled": true,
  "ip_blacklist": [
    "192.168.99.100"
  ],
  "domain_blacklist": [
    "test-blocked.local"
  ],
  "use_redis_blacklist": true,
  "log_only": true,
  "block_on_match": false,
  "refresh_interval": 300
}
```

## Integration with Threat Intelligence

### Automated Threat Feed Integration
```bash
#!/bin/bash
# /scripts/update_blacklists.sh - Update blacklists from threat feeds

# Download latest threat intelligence
curl -s "https://threatfeed.example.com/ips.txt" > /tmp/threat_ips.txt
curl -s "https://threatfeed.example.com/domains.txt" > /tmp/threat_domains.txt

# Validate and update blacklist files
if [ -s /tmp/threat_ips.txt ]; then
    cp /tmp/threat_ips.txt /etc/dfirewall/blocked_ips.txt
fi

if [ -s /tmp/threat_domains.txt ]; then
    cp /tmp/threat_domains.txt /etc/dfirewall/blocked_domains.txt
fi

# Update Redis blacklists
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ ]] || [[ -z "$ip" ]] && continue
    redis-cli SADD dfirewall:blacklist:ips "$ip"
done < /tmp/threat_ips.txt

while IFS= read -r domain; do
    [[ "$domain" =~ ^#.*$ ]] || [[ -z "$domain" ]] && continue
    redis-cli SADD dfirewall:blacklist:domains "$domain"
done < /tmp/threat_domains.txt

# Clean up
rm -f /tmp/threat_ips.txt /tmp/threat_domains.txt
```

### Cron Job for Regular Updates
```bash
# Add to crontab: update blacklists every hour
0 * * * * /scripts/update_blacklists.sh >/dev/null 2>&1
```

## Web UI Integration

### Adding IPs via Web UI
The Web UI provides interfaces for managing blacklists:
- Add IP addresses to blacklist
- Add domains to blacklist  
- View current blacklist entries
- Remove entries from blacklists

### API Endpoints for Blacklist Management
```bash
# Add IP to blacklist
curl -X POST http://localhost:8080/api/blacklist/ip/add \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.100.5"}'

# Add domain to blacklist
curl -X POST http://localhost:8080/api/blacklist/domain/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "malware.example.com"}'

# List current blacklists
curl http://localhost:8080/api/blacklist/list

# Remove IP from blacklist
curl -X POST http://localhost:8080/api/blacklist/ip/remove \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.100.5"}'
```

## Monitoring and Logging

### Blacklist Hit Logging
Configure logging for blacklist matches:
```json
{
  "log_only": false,
  "block_on_match": true
}
```

Logs will show:
```
2024-01-15 10:30:15 BLOCKED: Client 192.168.1.100 attempted to resolve malware.example.com (IP blacklist match)
2024-01-15 10:31:22 BLOCKED: Client 192.168.1.101 resolved bad.com to 203.0.113.5 (IP blacklist match)
```

### Monitoring Blacklist Effectiveness
```bash
# Count blacklist hits in logs
grep "BLOCKED.*blacklist" /var/log/dfirewall.log | wc -l

# Top blocked domains
grep "BLOCKED.*domain blacklist" /var/log/dfirewall.log | awk '{print $8}' | sort | uniq -c | sort -nr

# Top blocked IPs
grep "BLOCKED.*IP blacklist" /var/log/dfirewall.log | awk '{print $10}' | sort | uniq -c | sort -nr
```

### Blacklist Status via API
```bash
# Check blacklist configuration status
curl http://localhost:8080/api/config/status | jq '.blacklist_config'

# Get blacklist statistics
curl http://localhost:8080/api/blacklist/stats
```

## Performance Considerations

### File-Based Blacklists
- Large files may impact startup time
- Regular file I/O for refresh_interval
- Memory usage scales with blacklist size

### Redis-Based Blacklists
- Fast lookups using Redis sets
- Memory usage in Redis
- Network latency for Redis queries

### Optimization Tips
```json
{
  "refresh_interval": 3600,  // Reduce refresh frequency for large files
  "use_redis_blacklist": true,  // Use Redis for better performance
  "case_sensitive": false  // Reduce regex complexity
}
```

## Security Best Practices

### 1. Blacklist Sources
- Use reputable threat intelligence feeds
- Verify blacklist sources and update mechanisms
- Implement blacklist source validation

### 2. Access Control
- Restrict access to blacklist configuration files
- Secure Redis blacklist keys with authentication
- Monitor blacklist modifications

### 3. Regular Updates
- Automate blacklist updates from threat feeds
- Implement change monitoring and alerting
- Version control blacklist configurations

### 4. Testing and Validation
- Test blacklist rules before production deployment
- Validate blacklist entries for accuracy
- Monitor for false positives

## Troubleshooting

### Common Issues

#### Blacklist Not Loading
- Check file paths and permissions
- Verify JSON configuration syntax
- Review dfirewall startup logs

#### Redis Blacklist Issues
- Verify Redis connectivity and authentication
- Check Redis key names and data types
- Ensure Redis permissions for key access

#### Pattern Matching Problems
- Test regex patterns with online tools
- Verify wildcard syntax
- Check case sensitivity settings

#### Performance Issues
- Reduce refresh_interval for large files
- Optimize regex patterns
- Consider Redis for better performance

### Debug Commands
```bash
# Test blacklist configuration
export BLACKLIST_CONFIG=/path/to/blacklist.json
export DEBUG=true
./dfirewall

# Check Redis blacklist contents
redis-cli SMEMBERS dfirewall:blacklist:ips
redis-cli SMEMBERS dfirewall:blacklist:domains

# Validate JSON configuration
python3 -m json.tool /path/to/blacklist.json
```

## Migration Guide

### From File-Only to Redis Integration
1. Configure Redis blacklist keys in configuration
2. Import existing file entries to Redis:
```bash
# Import IP blacklist to Redis
while IFS= read -r ip; do
    [[ "$ip" =~ ^#.*$ ]] || [[ -z "$ip" ]] && continue
    redis-cli SADD dfirewall:blacklist:ips "$ip"
done < /etc/dfirewall/blocked_ips.txt
```

3. Enable Redis blacklist in configuration
4. Test and validate functionality

### Backup and Recovery
```bash
# Backup Redis blacklists
redis-cli SMEMBERS dfirewall:blacklist:ips > backup_ips.txt
redis-cli SMEMBERS dfirewall:blacklist:domains > backup_domains.txt

# Restore Redis blacklists
while IFS= read -r ip; do
    redis-cli SADD dfirewall:blacklist:ips "$ip"
done < backup_ips.txt
```

## Security Checklist

- [ ] Blacklist sources are trusted and verified
- [ ] Configuration files have appropriate permissions
- [ ] Redis blacklist keys are secured with authentication
- [ ] Regular automated updates are configured
- [ ] Blacklist changes are monitored and logged
- [ ] False positive procedures are established
- [ ] Backup and recovery procedures are tested
- [ ] Performance impact is monitored
- [ ] Access to blacklist management is restricted
- [ ] Blacklist effectiveness is regularly reviewed