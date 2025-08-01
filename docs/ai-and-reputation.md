# AI and Reputation Checking

This document provides comprehensive guidance for configuring AI-powered threat detection and reputation checking in dfirewall.

## Overview

dfirewall integrates with leading threat intelligence providers and AI services to provide real-time security analysis of DNS requests, domain reputation checking, and intelligent threat detection.

## IP and Domain Reputation Checking

### Supported Providers

#### VirusTotal
- **IP & Domain Reputation**: Comprehensive threat intelligence database
- **Multi-Engine Analysis**: Results from 70+ antivirus engines
- **API Key Required**: Free and premium plans available
- **Rate Limits**: 4 requests/minute (free), 1000/minute (premium)

#### AbuseIPDB  
- **IP Reputation**: Community-driven IP abuse reporting
- **Confidence Scoring**: Percentage-based threat confidence
- **Categories**: Detailed abuse category classification
- **API Key Required**: Free registration available

#### URLVoid
- **Domain Reputation**: Multi-engine domain analysis
- **Security Vendors**: Aggregates 30+ security engines
- **Website Scanning**: Real-time website safety analysis
- **API Key Required**: Paid service

#### Custom Providers
- **REST API Integration**: Support for any HTTP-based threat intelligence API
- **Flexible Authentication**: Custom headers and authentication methods
- **Configurable Endpoints**: Adaptable URL patterns and response parsing

### Configuration

Create a reputation configuration file and set `REPUTATION_CONFIG=/path/to/reputation.json`:

```json
{
  "enabled": true,
  "min_threat_score": 0.7,
  "cache_results": true,
  "cache_expiration": 3600,
  "checkers": [
    {
      "name": "virustotal_domain_checker",
      "type": "domain",
      "provider": "virustotal",
      "enabled": true,
      "api_key": "your_virustotal_api_key",
      "base_url": "https://www.virustotal.com/api/v3",
      "timeout": 10,
      "rate_limit": 4,
      "threshold": 5.0,
      "headers": {
        "x-apikey": "your_virustotal_api_key"
      },
      "query_format": "/domains/{target}"
    },
    {
      "name": "abuseipdb_ip_checker", 
      "type": "ip",
      "provider": "abuseipdb",
      "enabled": true,
      "api_key": "your_abuseipdb_api_key",
      "base_url": "https://api.abuseipdb.com/api/v2",
      "timeout": 10,
      "rate_limit": 10,
      "threshold": 75.0,
      "headers": {
        "Key": "your_abuseipdb_api_key",
        "Accept": "application/json"
      },
      "query_format": "/check?ipAddress={target}&maxAgeInDays=90"
    }
  ]
}
```

### Configuration Options

#### Global Settings
- **`enabled`**: Enable/disable reputation checking globally
- **`min_threat_score`**: Minimum score to consider malicious (0.0-1.0)
- **`cache_results`**: Cache reputation results to reduce API calls
- **`cache_expiration`**: Cache TTL in seconds

#### Per-Checker Settings
- **`name`**: Unique identifier for the checker
- **`type`**: Target type ("ip", "domain", or "both")
- **`provider`**: Provider identifier for logging
- **`enabled`**: Enable/disable this specific checker
- **`api_key`**: Authentication key for the service
- **`base_url`**: Base URL for API endpoints
- **`timeout`**: HTTP request timeout in seconds
- **`rate_limit`**: Maximum requests per minute
- **`threshold`**: Provider-specific threat threshold
- **`headers`**: Custom HTTP headers for authentication
- **`query_format`**: URL pattern with {target} placeholder

### Reputation Response Format

Each reputation check returns structured data:
```json
{
  "target": "example.com",
  "is_threat": true,
  "threat_score": 0.85,
  "checker_results": {
    "virustotal": {
      "score": 8.5,
      "engines_detected": 17,
      "total_engines": 20
    }
  },
  "categories": ["malware", "phishing"],
  "sources": ["virustotal", "urlvoid"],
  "checked_at": "2024-01-15T10:30:00Z",
  "cache_hit": false
}
```

## AI-Powered Threat Detection

### Supported AI Providers

#### OpenAI GPT Models
- **Domain Analysis**: Intelligent domain name pattern analysis
- **Traffic Anomaly Detection**: Behavioral analysis of DNS patterns
- **Threat Categorization**: AI-powered threat classification
- **API Key Required**: OpenAI account with API access

#### Anthropic Claude
- **Advanced Reasoning**: Deep analysis of threat indicators
- **Context-Aware Detection**: Comprehensive threat assessment
- **Multi-Modal Analysis**: Text and pattern analysis
- **API Key Required**: Anthropic API access

#### Local AI Models
- **Privacy-First**: No external API calls required
- **Custom Models**: Support for specialized security models
- **Offline Operation**: Works without internet connectivity
- **Resource Requirements**: GPU/CPU resources for inference

### AI Configuration

Create an AI configuration file and set `AI_CONFIG=/path/to/ai-config.json`:

```json
{
  "enabled": true,
  "provider": "openai",
  "api_key": "your_openai_api_key",
  "base_url": "https://api.openai.com/v1",
  "model": "gpt-4",
  "timeout": 30,
  
  "domain_analysis": true,
  "traffic_anomalies": true,
  "proactive_threat_hunting": false,
  
  "min_confidence": 0.8,
  "max_analysis_delay": 5,
  "cache_results": true,
  "cache_expiration": 7200
}
```

### AI Analysis Features

#### Domain Analysis
Analyzes domain names for suspicious patterns:
- **DGA Detection**: Domain Generation Algorithm identification
- **Typosquatting**: Detection of domain impersonation attempts
- **Suspicious TLDs**: Analysis of unusual top-level domains
- **Character Patterns**: Entropy and randomness analysis

#### Traffic Anomaly Detection
Monitors DNS request patterns for anomalies:
- **Request Frequency**: Unusual query patterns
- **Domain Diversity**: Abnormal domain request distribution
- **Temporal Patterns**: Time-based anomaly detection
- **Client Behavior**: Per-client traffic analysis

#### Threat Categorization
AI-powered classification of threats:
- **Malware C&C**: Command and control server identification
- **Phishing**: Phishing site detection and classification
- **Data Exfiltration**: Suspicious data transfer patterns
- **Botnet Activity**: Coordinated malicious activity detection

### AI Response Format

AI analysis returns detailed threat intelligence:
```json
{
  "target": "suspicious-domain.com",
  "request_id": "ai-req-123456",
  "is_malicious": true,
  "is_anomaly": false,
  "confidence": 0.92,
  "threat_score": 0.88,
  "threat_type": "phishing",
  "severity": "high",
  "reasoning": "Domain exhibits characteristics typical of phishing campaigns targeting financial institutions. The subdomain structure and SSL certificate patterns match known threat indicators.",
  "categories": ["phishing", "credential_theft"],
  "iocs": ["suspicious-domain.com", "185.199.108.153"],
  "related_threats": ["campaign_id_12345"],
  "provider": "openai",
  "model": "gpt-4",
  "analysis_time": 2847,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Integration Examples

### VirusTotal Integration
```json
{
  "name": "virustotal_comprehensive",
  "type": "both",
  "provider": "virustotal", 
  "enabled": true,
  "api_key": "your_vt_api_key",
  "base_url": "https://www.virustotal.com/api/v3",
  "timeout": 15,
  "rate_limit": 4,
  "threshold": 3.0,
  "headers": {
    "x-apikey": "your_vt_api_key"
  },
  "query_format": "/domains/{target}"
}
```

### OpenAI GPT-4 Integration
```json
{
  "enabled": true,
  "provider": "openai",
  "api_key": "sk-your-openai-api-key",
  "base_url": "https://api.openai.com/v1",
  "model": "gpt-4-turbo",
  "timeout": 30,
  "domain_analysis": true,
  "traffic_anomalies": true,
  "min_confidence": 0.85
}
```

### Local AI Model Integration
```json
{
  "enabled": true,
  "provider": "local",
  "base_url": "http://localhost:8000/v1",
  "model": "security-bert-large",
  "timeout": 10,
  "domain_analysis": true,
  "traffic_anomalies": false
}
```

## Performance Considerations

### API Rate Limiting
- **Respect Provider Limits**: Configure appropriate rate limits
- **Implement Backoff**: Handle rate limit responses gracefully
- **Cache Aggressively**: Reduce unnecessary API calls
- **Batch Requests**: Group multiple checks when possible

### Response Time Optimization
- **Async Processing**: Non-blocking reputation checks
- **Timeout Configuration**: Balance accuracy vs. performance
- **Cache Strategy**: Optimize cache TTL for your environment
- **Provider Selection**: Choose fastest providers for real-time checks

### Cost Management
- **API Key Management**: Monitor usage and costs
- **Selective Analysis**: Target high-risk domains/IPs only
- **Cache Optimization**: Reduce redundant API calls
- **Free Tier Utilization**: Maximize free API quotas

## Security Best Practices

### API Key Security
- **Environment Variables**: Store API keys securely
- **Key Rotation**: Regularly rotate API keys
- **Access Logging**: Monitor API key usage
- **Principle of Least Privilege**: Use minimal required permissions

### Data Privacy
- **Log Sanitization**: Avoid logging sensitive domain information
- **Cache Security**: Secure reputation cache data
- **Provider Selection**: Choose privacy-conscious providers
- **Data Retention**: Implement appropriate data retention policies

### Threat Response
- **Automated Blocking**: Configure automatic threat response
- **Alert Generation**: Set up threat detection alerts
- **Incident Response**: Integrate with security orchestration tools
- **False Positive Management**: Handle and learn from false positives

## Troubleshooting

### Common Issues

#### API Authentication Failures
- Verify API key validity and permissions
- Check API key format and headers
- Ensure rate limits are not exceeded
- Validate base URL and endpoint paths

#### Performance Issues
- Monitor API response times
- Optimize cache configuration
- Review rate limiting settings
- Consider provider alternatives

#### False Positives/Negatives
- Adjust threat score thresholds
- Review provider-specific scoring
- Implement manual override capabilities
- Maintain whitelist for known-good domains

### Debug Commands
```bash
# Test reputation checking
curl -X POST http://localhost:8080/api/reputation/check \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "type": "domain"}'

# Test AI analysis
curl -X POST http://localhost:8080/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "suspicious.com", "type": "domain"}'

# Check configuration status
curl http://localhost:8080/api/config/status | jq '.reputation_config,.ai_config'
```

## Monitoring and Metrics

### Key Metrics
- **API Response Times**: Track provider performance
- **Cache Hit Rates**: Monitor cache effectiveness
- **Threat Detection Rates**: Measure security effectiveness  
- **False Positive Rates**: Track accuracy metrics
- **API Cost Tracking**: Monitor usage and costs

### Health Monitoring
```bash
# Check reputation service health
curl http://localhost:8080/api/health | jq '.reputation_status'

# Monitor API rate limits
curl http://localhost:8080/api/reputation/stats

# Review recent threat detections
curl http://localhost:8080/api/reputation/recent
```

### Log Analysis
```bash
# Review reputation decisions
grep "REPUTATION" /var/log/dfirewall.log | tail -50

# Monitor AI analysis results
grep "AI_ANALYSIS" /var/log/dfirewall.log | jq .

# Track blocked threats
grep "BLOCKED.*reputation\|BLOCKED.*ai" /var/log/dfirewall.log
```

## Advanced Configuration

### Multi-Provider Setup
```json
{
  "enabled": true,
  "min_threat_score": 0.6,
  "checkers": [
    {
      "name": "virustotal_primary",
      "type": "both",
      "provider": "virustotal",
      "enabled": true,
      "weight": 0.4
    },
    {
      "name": "abuseipdb_secondary", 
      "type": "ip",
      "provider": "abuseipdb",
      "enabled": true,
      "weight": 0.3
    },
    {
      "name": "urlvoid_tertiary",
      "type": "domain", 
      "provider": "urlvoid",
      "enabled": true,
      "weight": 0.3
    }
  ]
}
```

### Threat Intelligence Feeds
```json
{
  "enabled": true,
  "threat_feeds": [
    {
      "name": "corporate_threat_intel",
      "url": "https://intel.company.com/api/threats",
      "api_key": "corporate_intel_key",
      "refresh_interval": 300,
      "format": "json"
    }
  ]
}
```

## Security Checklist

- [ ] API keys are stored securely in environment variables
- [ ] Rate limits are configured appropriately for each provider
- [ ] Cache TTL is optimized for security vs. performance
- [ ] Threat score thresholds are tuned for your environment
- [ ] False positive handling procedures are established
- [ ] API usage and costs are monitored
- [ ] Threat detection alerts are configured
- [ ] Log retention policies are implemented
- [ ] Provider redundancy is configured for critical environments
- [ ] Regular testing of threat detection capabilities is performed