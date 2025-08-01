# Redis Security Configuration

This document provides comprehensive guidance for securing Redis connections in dfirewall deployments.

## Overview

dfirewall stores firewall rules, DNS mappings, and blacklist data in Redis. Proper Redis security is critical for protecting your network security policies and preventing unauthorized access to your firewall rules.

## Security Configuration Options

### Authentication

#### Basic Password Authentication
```bash
# Set Redis password in connection URL
REDIS=redis://:password@127.0.0.1:6379

# Or set password separately (overrides URL password)
REDIS_PASSWORD=your_secure_password
```

#### Redis AUTH Command
Redis uses the `AUTH` command for authentication. Ensure your Redis server is configured with:
```redis
# In redis.conf
requirepass your_secure_password
```

### TLS/SSL Encryption

#### Enable TLS Connection
```bash
# Enable TLS encryption for Redis connection
REDIS_TLS=true
REDIS=rediss://username:password@redis.example.com:6380
```

#### Mutual TLS (mTLS) Authentication
For enhanced security, use client certificates:
```bash
REDIS_TLS=true
REDIS_TLS_CERT=/path/to/client.crt      # Client certificate
REDIS_TLS_KEY=/path/to/client.key       # Client private key
REDIS_TLS_CA=/path/to/ca.crt            # Certificate Authority
REDIS_TLS_SERVER_NAME=redis.example.com # Server name for cert verification
```

#### TLS Certificate Verification
```bash
# Skip certificate verification (NOT recommended for production)
REDIS_TLS_SKIP_VERIFY=true

# Verify certificates (default and recommended)
REDIS_TLS_SKIP_VERIFY=false
```

### Connection Security

#### Network Security
- **Bind Address**: Configure Redis to bind only to required interfaces
- **Firewall Rules**: Restrict Redis port (6379/6380) access
- **VPN/Private Networks**: Use Redis over secure networks only

#### Redis Configuration Security
```redis
# redis.conf security settings
bind 127.0.0.1 10.0.0.100           # Bind to specific IPs only
protected-mode yes                   # Enable protected mode
requirepass your_secure_password     # Require authentication
rename-command FLUSHDB ""           # Disable dangerous commands
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG ""
```

## Performance and Reliability Configuration

### Connection Pool Settings
```bash
REDIS_POOL_SIZE=10              # Maximum concurrent connections
REDIS_MAX_RETRIES=3             # Connection retry attempts
REDIS_DIAL_TIMEOUT=5s           # Connection establishment timeout
REDIS_READ_TIMEOUT=3s           # Read operation timeout
REDIS_WRITE_TIMEOUT=3s          # Write operation timeout
```

### Connection Pool Optimization
- **Pool Size**: Set based on expected concurrent DNS queries
- **Timeouts**: Balance between responsiveness and stability
- **Retries**: Configure for network reliability

## Redis High Availability

### Redis Sentinel
For production deployments, consider Redis Sentinel for automatic failover:
```bash
# Connect to Redis Sentinel cluster
REDIS=redis-sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster
REDIS_PASSWORD=your_redis_password
```

### Redis Cluster
For high throughput and data partitioning:
```bash
# Connect to Redis Cluster
REDIS=redis-cluster://node1:6379,node2:6379,node3:6379
```

## Security Best Practices

### 1. Strong Authentication
- Use strong, unique passwords for Redis authentication
- Rotate passwords regularly
- Consider key-based authentication for automated systems

### 2. Encryption in Transit
- Always use TLS in production environments
- Implement mutual TLS for sensitive deployments
- Verify TLS certificates properly

### 3. Network Security
- Use Redis over private networks or VPNs
- Implement firewall rules to restrict Redis access
- Monitor Redis connections and access patterns

### 4. Access Control
- Use Redis ACL (Access Control Lists) for fine-grained permissions
- Create dedicated Redis users for dfirewall
- Limit command access based on requirements

### 5. Monitoring and Logging
- Monitor Redis connection health via `/api/health` endpoint
- Log authentication failures and connection issues
- Set up alerts for Redis connection problems

## Example Configurations

### Development Environment
```bash
# Local Redis with basic password
REDIS=redis://:dev_password@127.0.0.1:6379
REDIS_POOL_SIZE=5
REDIS_DIAL_TIMEOUT=3s
```

### Production Environment
```bash
# Secure Redis with TLS and mTLS
REDIS=rediss://dfirewall:secure_password@redis.prod.example.com:6380
REDIS_TLS=true
REDIS_TLS_CERT=/etc/ssl/certs/dfirewall-client.crt
REDIS_TLS_KEY=/etc/ssl/private/dfirewall-client.key
REDIS_TLS_CA=/etc/ssl/certs/ca.crt
REDIS_TLS_SERVER_NAME=redis.prod.example.com
REDIS_POOL_SIZE=20
REDIS_MAX_RETRIES=5
REDIS_DIAL_TIMEOUT=10s
REDIS_READ_TIMEOUT=5s
REDIS_WRITE_TIMEOUT=5s
```

### High Availability Environment
```bash
# Redis Sentinel with TLS
REDIS=redis-sentinel://sentinel1.prod.example.com:26379,sentinel2.prod.example.com:26379/mymaster
REDIS_PASSWORD=production_password
REDIS_TLS=true
REDIS_TLS_CA=/etc/ssl/certs/redis-ca.crt
REDIS_POOL_SIZE=30
```

## Troubleshooting

### Common Issues

#### Connection Refused
- Check Redis server status and network connectivity
- Verify firewall rules and port accessibility
- Ensure Redis is bound to the correct interface

#### Authentication Failed
- Verify password configuration in both dfirewall and Redis
- Check Redis ACL settings if using Redis 6+
- Ensure password special characters are properly escaped

#### TLS Certificate Errors
- Verify certificate paths and permissions
- Check certificate validity and expiration
- Ensure server name matches certificate CN/SAN
- Use `REDIS_TLS_SKIP_VERIFY=true` for testing only

#### Performance Issues
- Monitor connection pool utilization
- Adjust timeout values based on network latency
- Consider increasing pool size for high-throughput scenarios

### Health Monitoring
Check Redis connection status via the dfirewall API:
```bash
curl http://localhost:8080/api/health
```

Expected healthy response:
```json
{
  "status": "ok",
  "redis_status": "connected",
  "checks": {
    "redis_ping": "ok",
    "redis_info": "ok"
  }
}
```

## Security Checklist

- [ ] Strong Redis password configured
- [ ] TLS encryption enabled for production
- [ ] Client certificates configured (if using mTLS)
- [ ] Redis bound to secure network interfaces only
- [ ] Firewall rules restricting Redis access
- [ ] Redis dangerous commands disabled
- [ ] Connection monitoring implemented
- [ ] Password rotation schedule established
- [ ] Certificate expiration monitoring set up
- [ ] Backup and recovery procedures tested