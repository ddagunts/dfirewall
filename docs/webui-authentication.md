# Web UI Authentication and Security

This document provides comprehensive guidance for configuring authentication and security for the dfirewall Web UI.

## Overview

The dfirewall Web UI provides a web-based interface for managing firewall rules, blacklists, and monitoring system status. It supports multiple authentication methods and security features to protect your firewall management interface.

## Authentication Methods

### 1. HTTPS/TLS Configuration

#### Enable HTTPS
```bash
export WEBUI_HTTPS_ENABLED=true
export WEBUI_CERT_FILE=/path/to/certificate.crt
export WEBUI_KEY_FILE=/path/to/private.key
```

#### Generate Self-Signed Certificate
Use the provided script to generate certificates for development/testing:
```bash
# Generate certificate for localhost
./scripts/generate-cert.sh localhost ./certs

# Generate certificate for specific hostname
./scripts/generate-cert.sh firewall.example.com ./certs

# Use generated certificates
export WEBUI_CERT_FILE=./certs/dfirewall.crt
export WEBUI_KEY_FILE=./certs/dfirewall.key
```

#### Production TLS Certificates
For production environments, use certificates from a trusted Certificate Authority:
```bash
# Let's Encrypt example
export WEBUI_CERT_FILE=/etc/letsencrypt/live/firewall.example.com/fullchain.pem
export WEBUI_KEY_FILE=/etc/letsencrypt/live/firewall.example.com/privkey.pem
```

### 2. Password Authentication

#### Basic Setup
```bash
export WEBUI_PASSWORD_AUTH=true
export WEBUI_USERNAME=admin
export WEBUI_PASSWORD=your_secure_password
```

#### Password Security
- Passwords are automatically hashed using bcrypt with default cost (10)
- Plain text passwords in environment variables are hashed on startup
- Pre-hashed passwords (starting with `$2a$` or `$2b$`) are used as-is

#### Generate Secure Password Hash
```bash
# Using Go to generate bcrypt hash
go run -c 'package main
import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)
func main() {
    hash, _ := bcrypt.GenerateFromPassword([]byte("your_password"), bcrypt.DefaultCost)
    fmt.Println(string(hash))
}'
```

### 3. LDAP Authentication

#### Basic LDAP Configuration
```bash
export WEBUI_LDAP_AUTH=true
export WEBUI_LDAP_SERVER=ldap.example.com
export WEBUI_LDAP_PORT=389
export WEBUI_LDAP_BASE_DN="dc=example,dc=com"
export WEBUI_LDAP_USER_ATTR=uid
```

#### LDAP with Service Account
```bash
export WEBUI_LDAP_BIND_DN="cn=service,dc=example,dc=com"
export WEBUI_LDAP_BIND_PASS=service_account_password
export WEBUI_LDAP_SEARCH_FILTER="(objectClass=person)"
```

#### LDAP over TLS (LDAPS)
```bash
export WEBUI_LDAP_SERVER=ldaps.example.com
export WEBUI_LDAP_PORT=636
```

#### Active Directory Configuration
```bash
export WEBUI_LDAP_SERVER=ad.company.com
export WEBUI_LDAP_PORT=389
export WEBUI_LDAP_BASE_DN="dc=company,dc=com"
export WEBUI_LDAP_BIND_DN="cn=dfirewall,ou=Service Accounts,dc=company,dc=com"
export WEBUI_LDAP_BIND_PASS=service_password
export WEBUI_LDAP_USER_ATTR=sAMAccountName
export WEBUI_LDAP_SEARCH_FILTER="(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

### 4. Header-Based Authentication

#### Basic Header Authentication
```bash
export WEBUI_HEADER_AUTH=true
export WEBUI_HEADER_NAME=X-Remote-User
export WEBUI_HEADER_VALUES=admin,operator,viewer
```

#### Trusted Proxy Configuration
```bash
export WEBUI_TRUSTED_PROXIES=192.168.1.100/24,10.0.0.0/8,172.16.0.0/12
```

#### Common Header Authentication Scenarios

**Nginx with auth_request:**
```bash
export WEBUI_HEADER_NAME=X-Auth-User
export WEBUI_TRUSTED_PROXIES=127.0.0.1,::1
```

**Apache with mod_auth:**
```bash
export WEBUI_HEADER_NAME=REMOTE_USER
export WEBUI_TRUSTED_PROXIES=192.168.1.10
```

**Cloudflare Access:**
```bash
export WEBUI_HEADER_NAME=Cf-Access-Authenticated-User-Email
export WEBUI_TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22
```

## Session Management

### Session Configuration
```bash
export WEBUI_SESSION_SECRET=your-long-random-secret-key-here
export WEBUI_SESSION_EXPIRY=24  # Hours
```

### Session Security Features
- JWT-based session tokens
- Secure, HttpOnly cookies
- SameSite=Strict cookie attribute
- Automatic session cleanup
- Session invalidation on logout

### Generate Secure Session Secret
```bash
# Generate random session secret
openssl rand -base64 32
```

## Configuration File Method

### JSON Configuration File
Create a comprehensive configuration file:
```json
{
  "https_enabled": true,
  "cert_file": "/etc/ssl/certs/dfirewall.crt",
  "key_file": "/etc/ssl/private/dfirewall.key",
  
  "password_auth": true,
  "username": "admin",
  "password": "$2a$10$hashed.password.here",
  
  "ldap_auth": false,
  "ldap_server": "ldap.example.com",
  "ldap_port": 389,
  "ldap_base_dn": "dc=example,dc=com",
  "ldap_bind_dn": "cn=service,dc=example,dc=com",
  "ldap_bind_pass": "service_password",
  "ldap_user_attr": "uid",
  "ldap_search_filter": "(objectClass=person)",
  
  "header_auth": false,
  "header_name": "X-Remote-User",
  "header_values": ["admin", "operator"],
  "trusted_proxies": ["192.168.1.100/24", "10.0.0.0/8"],
  
  "session_secret": "your-secure-session-secret-here",
  "session_expiry": 24
}
```

### Use Configuration File
```bash
export WEBUI_AUTH_CONFIG=/path/to/webui-auth.json
```

## Authentication Priority

When multiple authentication methods are enabled, they are checked in this order:

1. **Header Authentication** - Checked first if enabled
2. **Session Authentication** - JWT session from password/LDAP login
3. **Redirect to Login** - If no valid authentication found

## Deployment Scenarios

### Development Environment
```bash
# Simple password authentication with HTTP
export WEB_UI_PORT=8080
export WEBUI_PASSWORD_AUTH=true
export WEBUI_USERNAME=admin
export WEBUI_PASSWORD=dev_password
```

### Production Environment
```bash
# HTTPS with password authentication
export WEB_UI_PORT=8443
export WEBUI_HTTPS_ENABLED=true
export WEBUI_CERT_FILE=/etc/ssl/certs/dfirewall.crt
export WEBUI_KEY_FILE=/etc/ssl/private/dfirewall.key
export WEBUI_PASSWORD_AUTH=true
export WEBUI_USERNAME=admin
export WEBUI_PASSWORD="$2a$10$secure.hashed.password"
export WEBUI_SESSION_SECRET="$(openssl rand -base64 32)"
```

### Enterprise LDAP Environment
```bash
# HTTPS with LDAP authentication
export WEB_UI_PORT=8443
export WEBUI_HTTPS_ENABLED=true
export WEBUI_CERT_FILE=/etc/ssl/certs/dfirewall.crt  
export WEBUI_KEY_FILE=/etc/ssl/private/dfirewall.key
export WEBUI_LDAP_AUTH=true
export WEBUI_LDAP_SERVER=ldap.company.com
export WEBUI_LDAP_BASE_DN="dc=company,dc=com"
export WEBUI_LDAP_BIND_DN="cn=dfirewall,ou=services,dc=company,dc=com"
export WEBUI_LDAP_BIND_PASS=service_password
export WEBUI_SESSION_SECRET="$(openssl rand -base64 32)"
```

### Reverse Proxy Environment
```bash
# Header authentication behind Nginx/Apache
export WEB_UI_PORT=8080
export WEBUI_HEADER_AUTH=true
export WEBUI_HEADER_NAME=X-Auth-User
export WEBUI_TRUSTED_PROXIES=127.0.0.1,192.168.1.0/24
```

## Security Best Practices

### 1. Use HTTPS in Production
- Always enable HTTPS for production deployments
- Use valid TLS certificates from trusted CAs
- Configure proper TLS security headers

### 2. Strong Authentication
- Use strong passwords with multiple character types
- Implement password rotation policies
- Consider multi-factor authentication at proxy level

### 3. Session Security
- Use cryptographically secure session secrets
- Set appropriate session expiry times
- Implement session monitoring and anomaly detection

### 4. Network Security
- Restrict Web UI access to authorized networks
- Use firewalls to limit port access
- Consider VPN access for remote management

### 5. Monitoring and Logging
- Monitor authentication attempts and failures
- Log administrative actions and changes
- Set up alerts for suspicious activities

## Integration Examples

### Nginx Reverse Proxy with Authentication
```nginx
server {
    listen 443 ssl;
    server_name firewall.example.com;
    
    ssl_certificate /etc/ssl/certs/firewall.crt;
    ssl_certificate_key /etc/ssl/private/firewall.key;
    
    location /auth {
        internal;
        proxy_pass http://auth-service/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }
    
    location / {
        auth_request /auth;
        auth_request_set $user $upstream_http_x_user;
        proxy_set_header X-Auth-User $user;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### Apache with Basic Authentication
```apache
<VirtualHost *:443>
    ServerName firewall.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/firewall.crt
    SSLCertificateKeyFile /etc/ssl/private/firewall.key
    
    <Location />
        AuthType Basic
        AuthName "Firewall Management"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
        
        # Pass authenticated user to backend
        RewriteEngine On
        RewriteRule .* - [E=RU:%{REMOTE_USER}]
        RequestHeader set X-Remote-User %{RU}e
        
        ProxyPass http://127.0.0.1:8080/
        ProxyPassReverse http://127.0.0.1:8080/
    </Location>
</VirtualHost>
```

## Troubleshooting

### Common Issues

#### Login Page Not Appearing
- Check if authentication is enabled with any method
- Verify Web UI port is accessible
- Check browser console for JavaScript errors

#### Authentication Failures
- Verify credentials are correct
- Check LDAP server connectivity and configuration
- Review authentication logs in dfirewall output

#### Session Issues
- Verify session secret is set and consistent
- Check cookie settings and browser compatibility
- Ensure system time is synchronized

#### HTTPS Certificate Errors
- Verify certificate and key file paths
- Check certificate validity and expiration
- Ensure certificate matches server hostname

### Debug Mode
Enable debug logging to troubleshoot authentication issues:
```bash
export DEBUG=true
```

### Health Check
Monitor authentication system health:
```bash
curl -k https://firewall.example.com:8443/api/health
```

## Security Checklist

- [ ] HTTPS enabled with valid certificates
- [ ] Strong authentication method configured
- [ ] Session secrets are cryptographically secure
- [ ] Trusted proxy configuration is restrictive
- [ ] Network access is properly restricted
- [ ] Authentication monitoring is implemented
- [ ] Session expiry is appropriate for environment
- [ ] Backup authentication method available
- [ ] Certificate expiration monitoring set up
- [ ] Security headers are properly configured