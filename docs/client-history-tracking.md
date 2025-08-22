# Client History Tracking

dfirewall provides comprehensive historical DNS lookup tracking for security analysis, forensics, and network monitoring. This feature automatically captures and stores every DNS resolution performed through the firewall for later analysis.

## Overview

The historical tracking system records all DNS queries processed by dfirewall, storing them in Redis with efficient time-based indexing. This enables security teams to:

- Investigate DNS-based security incidents
- Analyze client browsing patterns and anomalies  
- Track domain resolution history for specific clients
- Perform forensic analysis of network activity
- Monitor DNS usage trends over time

## Data Storage

### Redis Storage Model
Historical data is stored using Redis sorted sets with the following structure:

- **Key Pattern**: `history:client:{clientIP}`
- **Scoring**: Unix timestamp for efficient time-range queries
- **Data Format**: JSON objects containing domain, resolved IPs, TTL, and metadata
- **Automatic Expiration**: Configurable retention period (default: 30 days)

### Data Structure
Each historical record contains:
```json
{
  "domain": "example.com",
  "resolved_ips": ["192.0.2.1", "192.0.2.2"],
  "ttl": 300,
  "timestamp": 1704067200,
  "query_type": "A"
}
```

## Configuration

### Environment Variables

#### `HISTORY_RETENTION_DAYS`
- **Default**: 30
- **Description**: Number of days to retain client DNS lookup history
- **Example**: `HISTORY_RETENTION_DAYS=90` (retain for 3 months)

Historical data automatically expires after the specified retention period to manage storage usage.

## API Access

### Historical Query Endpoint

**Endpoint**: `/api/client/history/{clientIP}`

**Method**: GET

**Parameters**:
- `start` (optional): Start timestamp for time range filtering
- `end` (optional): End timestamp for time range filtering  
- `days` (optional): Relative time period (1, 3, 7, 30 days)
- `limit` (optional): Maximum number of results (100, 500, 1000, 5000)

**Response Format**:
```json
{
  "client_ip": "192.168.1.100",
  "total_lookups": 1250,
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-07T23:59:59Z",
  "lookups": [
    {
      "domain": "example.com",
      "resolved_ips": ["192.0.2.1"],
      "ttl": 300,
      "timestamp": 1704067200
    }
  ]
}
```

### Example API Queries

**Get last 7 days of history**:
```bash
curl -X GET "http://localhost:8080/api/client/history/192.168.1.100?days=7&limit=1000"
```

**Get history for specific time range**:
```bash
curl -X GET "http://localhost:8080/api/client/history/192.168.1.100?start=1704067200&end=1704153600"
```

**Get recent 100 lookups**:
```bash
curl -X GET "http://localhost:8080/api/client/history/192.168.1.100?limit=100"
```

## Web UI Integration

The Web UI provides an interactive client history panel with the following features:

### Search Interface
- **Client IP Input**: Enter target client IP address
- **Time Range Selection**: 1 day, 3 days, 7 days, 30 days, or all available data
- **Result Limiting**: Choose between 100, 500, 1000, or 5000 results
- **Real-time Search**: Dynamic loading with progress indicators

### Results Display
- **Summary Statistics**: Total lookups and time period covered
- **Tabular View**: Domain, resolved IPs, timestamp, and TTL information
- **Time Formatting**: Human-readable timestamps with sorting capability
- **Error Handling**: Clear error messages for invalid queries or connection issues

### Access
Navigate to the Web UI and click the "📊 Client History" button to access the historical query interface.

## Security Considerations

### Data Privacy
- Historical data contains detailed DNS query information
- Consider data retention policies for compliance requirements
- Implement appropriate access controls for historical data

### Performance Impact
- Historical logging adds minimal overhead to DNS processing
- Redis sorted sets provide efficient time-range queries
- Automatic expiration prevents unbounded storage growth

### Access Control
- API endpoints require authentication (same as other Web UI features)
- Rate limiting applies (60 requests/minute per IP)
- Consider restricting access to authorized security personnel

## Use Cases

### Security Investigation
```bash
# Investigate suspicious client activity
curl -X GET "/api/client/history/192.168.1.100?days=30&limit=5000" | \
  jq '.lookups[] | select(.domain | contains("suspicious"))'
```

### Baseline Analysis
```bash
# Analyze normal browsing patterns for comparison
curl -X GET "/api/client/history/192.168.1.100?days=7&limit=1000" | \
  jq '.lookups[].domain' | sort | uniq -c | sort -nr
```

### Incident Response
```bash
# Get DNS activity during specific incident timeframe
curl -X GET "/api/client/history/192.168.1.100?start=1704067200&end=1704070800"
```

### Forensic Analysis
- Track domain resolution patterns before security incidents
- Identify command-and-control domains contacted by compromised hosts
- Correlate DNS queries with network security events
- Analyze DNS tunneling or data exfiltration attempts

## Troubleshooting

### Common Issues

**No historical data returned**:
- Verify client IP is correct and has made DNS queries through dfirewall
- Check that retention period hasn't expired
- Ensure Redis connectivity and key existence

**Performance issues with large queries**:
- Use time range filtering to limit query scope
- Implement result limiting for large datasets
- Consider Redis memory usage for extensive historical data

**Authentication failures**:
- Ensure Web UI authentication is properly configured
- Check session validity and login status
- Verify API endpoint permissions

### Monitoring

Monitor historical tracking system health:
```bash
# Check Redis key count for historical data
redis-cli EVAL "return #redis.call('keys', 'history:client:*')" 0

# Check total memory usage of historical keys
redis-cli --bigkeys -i 0.01 | grep history
```

## Integration Examples

### Custom Analytics Scripts
```bash
#!/bin/bash
# Generate daily DNS query statistics
CLIENT_IP="192.168.1.100"
TODAY=$(date +%s)
YESTERDAY=$((TODAY - 86400))

curl -s "/api/client/history/${CLIENT_IP}?start=${YESTERDAY}&end=${TODAY}" | \
  jq -r '.lookups[].domain' | \
  sort | uniq -c | sort -nr | \
  head -20 > daily_dns_report.txt
```

### SIEM Integration
Historical data can be exported for integration with SIEM systems:
```bash
# Export historical data in SIEM-friendly format
curl -s "/api/client/history/192.168.1.100?days=1" | \
  jq -r '.lookups[] | [.timestamp, .client_ip, .domain, (.resolved_ips | join(","))] | @csv'
```

This historical tracking capability provides powerful insights into DNS usage patterns and supports comprehensive network security monitoring and incident response workflows.