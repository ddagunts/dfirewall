# AI-Powered Threat Detection

This document provides comprehensive guidance for configuring AI-powered threat detection in dfirewall using machine learning and artificial intelligence providers.

## Overview

dfirewall integrates AI technology for domain analysis, traffic anomaly detection, and proactive threat hunting. This defensive security feature leverages machine learning models to identify sophisticated threats that traditional signature-based detection might miss.

## Supported AI Providers

### OpenAI GPT Models
- **Domain Analysis**: Intelligent domain name pattern analysis
- **Traffic Anomaly Detection**: Behavioral analysis of DNS patterns
- **Threat Categorization**: AI-powered threat classification
- **API Key Required**: OpenAI account with API access

### Anthropic Claude
- **Advanced Reasoning**: Deep analysis of threat indicators
- **Context-Aware Detection**: Comprehensive threat assessment
- **Multi-Modal Analysis**: Text and pattern analysis
- **API Key Required**: Anthropic API access

### Local AI Models
- **Privacy-First**: No external API calls required
- **Custom Models**: Support for specialized security models
- **Offline Operation**: Works without internet connectivity
- **Resource Requirements**: GPU/CPU resources for inference

## Configuration

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

## AI Analysis Features

### Domain Analysis
Analyzes domain names for suspicious patterns:
- **DGA Detection**: Domain Generation Algorithm identification
- **Typosquatting**: Detection of domain impersonation attempts
- **Suspicious TLDs**: Analysis of unusual top-level domains
- **Character Patterns**: Entropy and randomness analysis

### Traffic Anomaly Detection
Monitors DNS request patterns for anomalies:
- **Request Frequency**: Unusual query patterns
- **Domain Diversity**: Abnormal domain request distribution
- **Temporal Patterns**: Time-based anomaly detection
- **Client Behavior**: Per-client traffic analysis

### Threat Categorization
AI-powered classification of threats:
- **Malware C&C**: Command and control server identification
- **Phishing**: Phishing site detection and classification
- **Data Exfiltration**: Suspicious data transfer patterns
- **Botnet Activity**: Coordinated malicious activity detection

## Response Format

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

### Anthropic Claude Integration
```json
{
  "enabled": true,
  "provider": "anthropic",
  "api_key": "your-anthropic-api-key",
  "base_url": "https://api.anthropic.com/v1",
  "model": "claude-3-opus",
  "timeout": 30,
  "domain_analysis": true,
  "traffic_anomalies": true,
  "min_confidence": 0.9
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

### Response Time Optimization
- **Async Processing**: Non-blocking AI analysis
- **Timeout Configuration**: Balance accuracy vs. performance
- **Cache Strategy**: Optimize cache TTL for your environment
- **Model Selection**: Choose appropriate models for real-time analysis

### Resource Management
- **API Rate Limiting**: Manage API calls to avoid quotas
- **Local Model Resources**: Ensure adequate GPU/CPU for inference
- **Memory Usage**: Monitor memory consumption for large models
- **Concurrent Analysis**: Limit parallel AI requests

### Cost Management
- **API Usage Monitoring**: Track costs and token usage
- **Selective Analysis**: Target high-risk domains/patterns only
- **Cache Optimization**: Reduce redundant AI calls
- **Model Efficiency**: Choose cost-effective models for your use case

## Security Best Practices

### API Key Security
- **Environment Variables**: Store API keys securely
- **Key Rotation**: Regularly rotate API keys
- **Access Logging**: Monitor AI API usage
- **Scope Limitation**: Use minimal required API permissions

### Data Privacy
- **Local Processing**: Consider local models for sensitive data
- **Data Minimization**: Send only necessary data to AI providers
- **Log Sanitization**: Avoid logging sensitive information
- **Provider Selection**: Choose privacy-conscious AI providers

### Model Security
- **Prompt Injection Protection**: Validate and sanitize inputs
- **Output Validation**: Verify AI response format and content
- **Fallback Mechanisms**: Handle AI service failures gracefully
- **False Positive Management**: Implement human review processes

## Troubleshooting

### Common Issues

#### AI Service Failures
- Verify API key validity and permissions
- Check network connectivity to AI providers
- Monitor rate limits and quotas
- Validate model availability and parameters

#### Performance Issues
- Monitor AI response times
- Optimize cache configuration
- Review timeout settings
- Consider model alternatives

#### Accuracy Issues
- Adjust confidence thresholds
- Review AI model selection
- Implement feedback mechanisms
- Maintain training data quality

### Debug Commands
```bash
# Test AI analysis
curl -X POST http://localhost:8080/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "suspicious.com", "type": "domain"}'

# Check AI configuration status
curl http://localhost:8080/api/config/status | jq '.ai_config'
```

## Monitoring and Metrics

### Key Metrics
- **AI Response Times**: Track provider performance
- **Detection Accuracy**: Measure true/false positive rates
- **Token Usage**: Monitor API costs and consumption
- **Cache Effectiveness**: Track cache hit rates
- **Threat Categories**: Analyze threat type distribution

### Health Monitoring
```bash
# Check AI service health
curl http://localhost:8080/api/health | jq '.ai_status'

# Monitor AI usage statistics
curl http://localhost:8080/api/ai/stats

# Review recent AI detections
curl http://localhost:8080/api/ai/recent
```

### Log Analysis
```bash
# Monitor AI analysis results
grep "AI_ANALYSIS" /var/log/dfirewall.log | jq .

# Track AI-based blocks
grep "BLOCKED.*ai" /var/log/dfirewall.log

# Review AI performance metrics
grep "AI_METRICS" /var/log/dfirewall.log
```

## Advanced Configuration

### Multi-Model Setup
```json
{
  "enabled": true,
  "models": [
    {
      "name": "primary_analysis",
      "provider": "openai",
      "model": "gpt-4-turbo",
      "weight": 0.6,
      "use_cases": ["domain_analysis"]
    },
    {
      "name": "anomaly_detection",
      "provider": "local",
      "model": "anomaly-bert",
      "weight": 0.4,
      "use_cases": ["traffic_anomalies"]
    }
  ]
}
```

### Custom Threat Intelligence
```json
{
  "enabled": true,
  "custom_prompts": {
    "domain_analysis": "Analyze this domain for security threats focusing on: DGA patterns, typosquatting, suspicious TLDs, and phishing indicators.",
    "traffic_analysis": "Evaluate DNS traffic patterns for anomalies indicating: botnet activity, data exfiltration, or C&C communication."
  },
  "threat_categories": [
    "malware", "phishing", "botnet", "c2", "dga", "typosquatting"
  ]
}
```

## Security Checklist

- [ ] AI API keys are stored securely in environment variables
- [ ] Appropriate models are selected for security use cases
- [ ] Confidence thresholds are tuned for your environment
- [ ] Rate limits and quotas are monitored
- [ ] Data privacy requirements are met
- [ ] Fallback mechanisms are implemented for AI failures
- [ ] False positive review processes are established
- [ ] AI usage costs are monitored and controlled
- [ ] Local models are considered for sensitive environments
- [ ] Regular evaluation of AI detection accuracy is performed
