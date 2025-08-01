# Per-Client Script Configuration

This document provides comprehensive guidance for configuring per-client script execution in dfirewall.

## Overview

dfirewall supports advanced per-client script configuration, allowing different firewall policies and scripts for different client IP ranges or patterns. This enables fine-grained control over firewall behavior based on client identity, network location, or security requirements.

## Configuration File Structure

### Basic Configuration File
Create a JSON configuration file and set `SCRIPT_CONFIG=/path/to/config.json`:

```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/default_invoke.sh",
    "expire_script": "/scripts/default_expire.sh",
    "invoke_always": false,
    "environment": {
      "DEFAULT_POLICY": "deny"
    }
  },
  "clients": [
    {
      "client_pattern": "192.168.1.0/24",
      "description": "Corporate network",
      "invoke_script": "/scripts/corporate_invoke.sh",
      "invoke_always": true,
      "environment": {
        "SECURITY_LEVEL": "high",
        "AUDIT_LOG": "/var/log/corporate.log"
      }
    }
  ]
}
```

### Configuration Fields

#### Global Defaults
- **`version`**: Configuration file version (currently "1.0")
- **`defaults`**: Global fallback configuration used when no client-specific config matches

#### Default Section Fields
- **`invoke_script`**: Path to script executed when new IPs are encountered
- **`expire_script`**: Path to script executed when Redis keys expire
- **`invoke_always`**: Execute script for every IP encounter (not just new ones)
- **`environment`**: Environment variables passed to scripts

#### Client-Specific Configuration
- **`client_pattern`**: Pattern for matching client IPs (CIDR, single IP, or regex)
- **`description`**: Human-readable description for documentation
- **`invoke_script`**: Client-specific invoke script (overrides global)
- **`expire_script`**: Client-specific expire script (overrides global)  
- **`invoke_always`**: Client-specific invoke_always setting (overrides global)
- **`environment`**: Additional environment variables for this client

## Client Pattern Matching

### CIDR Notation
Match entire network ranges:
```json
{
  "client_pattern": "192.168.1.0/24",
  "description": "Main office network"
}
```

### Single IP Address
Match specific IP addresses:
```json
{
  "client_pattern": "10.0.0.100",
  "description": "Admin workstation"
}
```

### Regex Patterns
Use regex for complex matching:
```json
{
  "client_pattern": "^192\\.168\\.(10|20|30)\\.",
  "description": "Specific VLANs"
}
```

### IPv6 Support
Configure IPv6 client patterns:
```json
{
  "client_pattern": "2001:db8::/32",
  "description": "IPv6 corporate network"
}
```

## Script Execution Model

### Invoke Scripts
Executed when dfirewall encounters IP addresses (new or all, based on `invoke_always`):

**Script Parameters:**
- `$1`: Client IP address
- `$2`: Resolved IP address  
- `$3`: Domain name
- `$4`: TTL value

**Environment Variables:**
- Standard environment variables from configuration
- `CLIENT_IP`: Client making the DNS request
- `RESOLVED_IP`: IP address resolved from DNS
- `DOMAIN`: Domain that was resolved
- `TTL`: Time-to-live value

### Expire Scripts
Executed when Redis keys expire (TTL reaches zero):

**Script Parameters:**
- `$1`: Client IP address
- `$2`: Resolved IP address
- `$3`: Domain name

**Environment Variables:**
- Standard environment variables from configuration
- `CLIENT_IP`: Client that had the rule
- `RESOLVED_IP`: IP address that expired
- `DOMAIN`: Domain that expired

## Configuration Examples

### Corporate Environment
```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/default_allow.sh",
    "expire_script": "/scripts/default_cleanup.sh",
    "invoke_always": false,
    "environment": {
      "LOG_LEVEL": "info",
      "POLICY": "moderate"
    }
  },
  "clients": [
    {
      "client_pattern": "192.168.10.0/24",
      "description": "Executive network - high security",
      "invoke_script": "/scripts/executive_strict.sh",
      "expire_script": "/scripts/executive_cleanup.sh",
      "invoke_always": true,
      "environment": {
        "SECURITY_LEVEL": "maximum",
        "AUDIT_LOG": "/var/log/executive.log",
        "ALERT_EMAIL": "security@company.com"
      }
    },
    {
      "client_pattern": "192.168.20.0/24", 
      "description": "Development network - relaxed policy",
      "invoke_script": "/scripts/dev_permissive.sh",
      "invoke_always": false,
      "environment": {
        "SECURITY_LEVEL": "low",
        "ALLOW_WILDCARDS": "true"
      }
    },
    {
      "client_pattern": "192.168.30.0/24",
      "description": "Guest network - restricted access",
      "invoke_script": "/scripts/guest_restricted.sh",
      "environment": {
        "SECURITY_LEVEL": "minimal",
        "BLOCKED_PORTS": "22,23,3389",
        "ALLOWED_DOMAINS": "google.com,microsoft.com"
      }
    }
  ]
}
```

### Multi-Location Setup
```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/global_policy.sh",
    "expire_script": "/scripts/global_cleanup.sh",
    "environment": {
      "COMPANY": "ACME Corp",
      "GLOBAL_POLICY": "deny_by_default"
    }
  },
  "clients": [
    {
      "client_pattern": "10.1.0.0/16",
      "description": "New York office",
      "invoke_script": "/scripts/location_ny.sh",
      "environment": {
        "LOCATION": "NY",
        "TIMEZONE": "America/New_York",
        "COMPLIANCE": "SOX,HIPAA"
      }
    },
    {
      "client_pattern": "10.2.0.0/16", 
      "description": "London office",
      "invoke_script": "/scripts/location_london.sh",
      "environment": {
        "LOCATION": "LONDON",
        "TIMEZONE": "Europe/London",
        "COMPLIANCE": "GDPR"
      }
    },
    {
      "client_pattern": "10.100.0.0/16",
      "description": "Remote workers VPN",
      "invoke_script": "/scripts/remote_workers.sh",
      "invoke_always": true,
      "environment": {
        "LOCATION": "REMOTE",
        "EXTRA_LOGGING": "true",
        "MFA_REQUIRED": "true"
      }
    }
  ]
}
```

### Security-Based Segmentation
```json
{
  "version": "1.0",
  "defaults": {
    "invoke_script": "/scripts/default_moderate.sh",
    "expire_script": "/scripts/cleanup.sh"
  },
  "clients": [
    {
      "client_pattern": "172.16.1.0/24",
      "description": "DMZ servers - strict outbound",
      "invoke_script": "/scripts/dmz_strict.sh",
      "invoke_always": true,
      "environment": {
        "ZONE": "DMZ",
        "OUTBOUND_POLICY": "whitelist_only",
        "LOG_ALL": "true"
      }
    },
    {
      "client_pattern": "172.16.10.0/24",
      "description": "Internal servers - managed access",
      "invoke_script": "/scripts/internal_managed.sh",
      "environment": {
        "ZONE": "INTERNAL", 
        "BUSINESS_HOURS_ONLY": "true"
      }
    },
    {
      "client_pattern": "172.16.100.0/24",
      "description": "User workstations - standard policy",
      "invoke_script": "/scripts/workstation_standard.sh",
      "environment": {
        "ZONE": "WORKSTATION",
        "WEB_FILTERING": "enabled"
      }
    }
  ]
}
```

## Script Development

### Example Invoke Script
```bash
#!/bin/bash
# /scripts/corporate_invoke.sh

CLIENT_IP="$1"
RESOLVED_IP="$2"  
DOMAIN="$3"
TTL="$4"

# Log the request
echo "$(date): Client $CLIENT_IP resolved $DOMAIN to $RESOLVED_IP (TTL: $TTL)" >> "$AUDIT_LOG"

# Apply security level specific rules
case "$SECURITY_LEVEL" in
    "high")
        # High security: strict rules, extra logging
        /usr/local/bin/ipset create "client_${CLIENT_IP//./_}" hash:ip timeout "$TTL" 2>/dev/null
        /usr/local/bin/ipset add "client_${CLIENT_IP//./_}" "$RESOLVED_IP"
        
        # Create restrictive iptables rule
        iptables -I FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix "HIGH_SEC: "
        iptables -I FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        ;;
    "medium")
        # Medium security: standard rules
        /usr/local/bin/ipset create "client_${CLIENT_IP//./_}" hash:ip timeout "$TTL" 2>/dev/null
        /usr/local/bin/ipset add "client_${CLIENT_IP//./_}" "$RESOLVED_IP"
        iptables -I FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -j ACCEPT
        ;;
    "low")
        # Low security: permissive rules
        iptables -I FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -j ACCEPT
        ;;
esac

# Send alert for sensitive domains
if [[ "$DOMAIN" =~ \.(gov|mil)$ ]]; then
    echo "ALERT: $CLIENT_IP accessed government domain $DOMAIN" | mail -s "Security Alert" "$ALERT_EMAIL"
fi
```

### Example Expire Script
```bash
#!/bin/bash
# /scripts/corporate_expire.sh

CLIENT_IP="$1"
RESOLVED_IP="$2"
DOMAIN="$3"

# Log expiration
echo "$(date): Rule expired for $CLIENT_IP -> $RESOLVED_IP ($DOMAIN)" >> "$AUDIT_LOG"

# Clean up iptables rules
iptables -D FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -j ACCEPT 2>/dev/null
iptables -D FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -m conntrack --ctstate NEW,ESTABLISHED -j LOG --log-prefix "HIGH_SEC: " 2>/dev/null
iptables -D FORWARD -s "$CLIENT_IP" -d "$RESOLVED_IP" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2>/dev/null

# Clean up ipset
/usr/local/bin/ipset del "client_${CLIENT_IP//./_}" "$RESOLVED_IP" 2>/dev/null

# If ipset is empty, remove it
if [ "$(/usr/local/bin/ipset list "client_${CLIENT_IP//./_}" 2>/dev/null | grep -c "Number of entries: 0")" -eq 1 ]; then
    /usr/local/bin/ipset destroy "client_${CLIENT_IP//./_}" 2>/dev/null
fi
```

## Testing and Validation

### Configuration Validation
Validate your configuration file syntax:
```bash
# Test JSON syntax
python3 -m json.tool /path/to/script-config.json

# Test configuration loading (check dfirewall logs)
export SCRIPT_CONFIG=/path/to/script-config.json
export DEBUG=true
./dfirewall
```

### Script Testing
Test scripts with sample data:
```bash
# Test invoke script
/scripts/corporate_invoke.sh "192.168.1.100" "1.1.1.1" "example.com" "300"

# Test expire script  
/scripts/corporate_expire.sh "192.168.1.100" "1.1.1.1" "example.com"
```

### Pattern Matching Testing
Test client pattern matching:
```bash
# Test CIDR matching
python3 -c "
import ipaddress
client = ipaddress.ip_address('192.168.1.100')
network = ipaddress.ip_network('192.168.1.0/24')
print(f'{client} in {network}: {client in network}')
"
```

## Monitoring and Troubleshooting

### Configuration Status
Check configuration loading status via API:
```bash
curl http://localhost:8080/api/config/status
```

### Script Execution Monitoring
Monitor script execution:
```bash
# Enable debug logging
export DEBUG=true

# Monitor script execution in logs
tail -f /var/log/dfirewall.log | grep -E "(SCRIPT|ERROR)"
```

### Common Issues

#### Script Not Executing
- Verify script path exists and is executable
- Check script permissions (`chmod +x /path/to/script.sh`)
- Review client pattern matching logic
- Enable debug logging to see pattern matching

#### Environment Variables Not Set
- Verify environment variables in configuration
- Check script receives variables correctly
- Test with simple debug script

#### Pattern Matching Issues
- Test patterns with online regex/CIDR tools
- Verify IPv4/IPv6 address formats
- Check for typos in IP addresses and CIDR notation

## Best Practices

### 1. Script Security
- Use absolute paths for all commands
- Validate input parameters in scripts
- Implement proper error handling
- Use safe shell scripting practices

### 2. Configuration Management
- Version control your configuration files
- Test configuration changes in development
- Implement configuration validation
- Document client patterns and purposes

### 3. Performance Considerations
- Keep scripts lightweight and fast
- Avoid blocking operations in scripts
- Use efficient firewall rule management
- Monitor script execution times

### 4. Monitoring and Logging
- Implement comprehensive logging
- Monitor script execution success/failure
- Set up alerts for script errors
- Track firewall rule creation/deletion

### 5. Security Hardening
- Run scripts with minimal privileges
- Validate all input parameters
- Implement rate limiting for script execution
- Use secure temporary file handling

## Migration and Upgrades

### Migrating from Global Scripts
To migrate from global `INVOKE_SCRIPT`/`EXPIRE_SCRIPT` to per-client configuration:

1. Create configuration file with global scripts in defaults
2. Test configuration loading
3. Gradually add client-specific overrides
4. Remove global environment variables once satisfied

### Configuration File Versioning
Future versions may introduce new fields. Always specify version:
```json
{
  "version": "1.0",
  // ... rest of configuration
}
```

## Security Checklist

- [ ] Scripts have proper file permissions (executable, not world-writable)
- [ ] Script paths use absolute references
- [ ] Input validation implemented in all scripts
- [ ] Error handling prevents information disclosure
- [ ] Logging captures security-relevant events
- [ ] Configuration file is protected from unauthorized access
- [ ] Script execution is monitored and alerted
- [ ] Client patterns are as specific as possible
- [ ] Environment variables don't contain sensitive data
- [ ] Backup and recovery procedures tested