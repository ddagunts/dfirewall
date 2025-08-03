# dfirewall Integration Test Suite

This document describes the comprehensive integration test suite for dfirewall, designed to test configuration combinations that were missing from the original test coverage.

## Overview

The integration test suite covers critical configuration combination scenarios that were not tested in the original codebase:

- **Redis configuration combinations** (TLS, authentication, connection pooling)
- **Web UI authentication method combinations** (password, LDAP, header-based)
- **Script configuration inheritance** (global vs client-specific overrides)
- **Security feature interactions** (blacklisting + reputation + AI + custom scripts)
- **Resource exhaustion scenarios** (memory, connections, file descriptors)
- **Configuration validation chains** (dependency validation, conflict detection)

## Test Files

### Core Framework
- `integration_test.go` - Base integration test framework and utilities
- `run_integration_tests.go` - Test runner with category management

### Test Categories
- `redis_integration_test.go` - Redis configuration combination tests
- `webui_auth_integration_test.go` - Web UI authentication combination tests
- `script_config_integration_test.go` - Script configuration inheritance tests
- `security_integration_test.go` - Security feature combination tests
- `performance_integration_test.go` - Resource exhaustion and performance tests
- `validation_chain_integration_test.go` - Configuration validation chain tests

## Running Tests

### Prerequisites

Before running integration tests, ensure:

1. **Redis Server**: Running on `localhost:6379`
2. **Available Ports**: 8080-8090 for Web UI tests
3. **File System**: Writable `/tmp` directory
4. **Network**: Internet access for reputation API tests (optional)
5. **Resources**: Sufficient memory/CPU for stress tests

### Basic Usage

```bash
# Run all integration tests
go test -v ./... -tags=integration

# Run specific test categories
go run run_integration_tests.go -only=redis,webui

# Skip certain categories
go run run_integration_tests.go -skip=performance,security

# Verbose output with detailed logging
go run run_integration_tests.go -verbose

# Custom timeout (default: 30 minutes)
go run run_integration_tests.go -timeout=60m
```

### Test Categories

#### 1. Redis Configuration Tests (`redis`)

Tests Redis configuration combinations:

- **Basic connection** without authentication
- **Password authentication** with various settings
- **TLS encryption** with different certificate configurations
- **Client certificate authentication**
- **Connection pool configuration** and stress testing
- **Failover scenarios** and error handling
- **Performance benchmarks** under load

**Key Test Cases:**
- Redis + TLS + Password authentication
- Connection pool exhaustion scenarios
- TLS certificate validation
- Concurrent connection stress testing

#### 2. Web UI Authentication Tests (`webui`)

Tests Web UI authentication method combinations:

- **Password authentication** only
- **HTTPS + password authentication**
- **LDAP authentication** configuration
- **Header-based authentication**
- **Multiple authentication methods** (conflict detection)
- **Session management** configuration
- **Environment variable overrides**

**Key Test Cases:**
- Multiple auth methods enabled simultaneously
- HTTPS certificate validation
- Session timeout and security settings
- Authentication method precedence

#### 3. Script Configuration Tests (`scripts`)

Tests script configuration inheritance and pattern matching:

- **Global script configuration** without client overrides
- **Client-specific overrides** of global settings
- **Complex pattern matching** (IP, CIDR, regex, IPv6)
- **Environment variable inheritance** between defaults and clients
- **Configuration precedence** (env vars → client config → defaults)
- **Invalid pattern handling**
- **Mixed IPv4/IPv6 patterns**

**Key Test Cases:**
- Pattern matching performance with 500+ complex regex patterns
- Environment variable inheritance and override behavior
- Script path validation and error handling

#### 4. Security Feature Tests (`security`)

Tests interactions between security features:

- **Basic blacklisting** (IP and domain)
- **Reputation checking** with multiple providers
- **AI-powered threat detection** configuration
- **Custom script validation**
- **All security features combined**
- **Security feature conflicts** and resolution
- **Performance optimization** with caching
- **Failover behavior** when security services fail

**Key Test Cases:**
- All security features enabled simultaneously
- Conflicting blacklist/whitelist entries
- Security feature failover and recovery
- Performance impact of security processing

#### 5. Performance and Resource Tests (`performance`)

Tests resource exhaustion and performance scenarios:

- **High Redis connection pools** under load
- **Memory usage** with all features enabled
- **Concurrent DNS queries** (5000+ queries, 100+ concurrent)
- **Large configuration files** (10k+ IP blacklist entries)
- **Script execution floods**
- **Redis connection exhaustion**
- **File descriptor usage**
- **CPU-intensive pattern matching**

**Key Test Cases:**
- System behavior with 10,000 blacklist entries
- Memory usage under sustained load
- Performance with 500+ complex regex patterns
- Connection pool exhaustion recovery

#### 6. Configuration Validation Tests (`validation`)

Tests configuration validation and dependency chains:

- **Redis-dependent features** failing without Redis
- **Upstream DNS dependency** validation
- **Port conflict detection** between DNS and Web UI
- **Script path validation** and accessibility
- **Configuration file dependencies**
- **Environment vs file precedence** validation
- **Circular dependency detection**
- **Resource availability validation**
- **Complete valid configuration** chains

**Key Test Cases:**
- Circular dependencies between configuration files
- Invalid configuration rollback behavior
- Cross-configuration validation chains
- Version compatibility checking

## Test Architecture

### IntegrationTestSuite

The `IntegrationTestSuite` provides:

- **Environment management**: Save/restore environment variables
- **Temporary file creation**: Config files and scripts
- **Resource validation**: Redis connectivity, Web UI access, DNS resolution
- **Cleanup management**: Automatic resource cleanup

### ConfigurationCombination

Each test case is defined as a `ConfigurationCombination`:

```go
type ConfigurationCombination struct {
    Name        string                    // Test name
    Description string                    // Test description
    EnvVars     map[string]string        // Environment variables to set
    ConfigFiles map[string]interface{}   // Configuration files to create
    ExpectError bool                     // Whether test should fail
    Validate    func(*testing.T, *IntegrationTestSuite) error // Validation function
}
```

### Test Categories

Tests are organized into categories with:

- **Prerequisites**: Required system state
- **Setup/Teardown**: Category-specific environment management
- **Test Lists**: Specific test functions in each category

## Expected Failures

Some tests are designed to fail and verify error handling:

- **TLS tests without certificates** → Certificate validation errors
- **LDAP tests without server** → Connection failures
- **Invalid configuration tests** → Validation errors
- **Resource exhaustion tests** → Graceful degradation

## Performance Baselines

The test suite establishes performance baselines:

- **DNS Query Rate**: >100 QPS minimum
- **Configuration Loading**: <1 second for 1000 client patterns
- **Memory Usage**: <50MB for 5000 client patterns
- **Concurrent Operations**: <10% error rate under stress

## Continuous Integration

For CI/CD integration:

```yaml
# Example GitHub Actions configuration
- name: Run Integration Tests
  run: |
    docker-compose -f docker-compose.test.yml up -d redis
    go run run_integration_tests.go -timeout=10m -skip=performance
    docker-compose -f docker-compose.test.yml down
```

## Debugging Failed Tests

When tests fail:

1. **Check Prerequisites**: Verify Redis, ports, file system access
2. **Review Logs**: Use `-verbose` flag for detailed output
3. **Isolate Categories**: Run specific test categories with `-only`
4. **Check Environment**: Verify required environment variables
5. **Resource Monitoring**: Monitor memory, CPU, file descriptors during tests

## Contributing

When adding new configuration options:

1. **Add Integration Tests**: Cover new configuration combinations
2. **Update Test Categories**: Add to appropriate test category
3. **Document Prerequisites**: Update prerequisite requirements
4. **Test Interactions**: Verify interactions with existing features
5. **Performance Impact**: Add performance tests if applicable

## Troubleshooting

Common issues and solutions:

### Redis Connection Failures
```bash
# Check Redis status
docker ps | grep redis
# Restart Redis
docker-compose restart redis
```

### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :8080
# Use alternative ports
go run run_integration_tests.go -only=webui # Uses port 8080
```

### Memory Issues
```bash
# Monitor memory during tests
while true; do free -h; sleep 5; done
# Reduce test load
go run run_integration_tests.go -skip=performance
```

### Permission Issues
```bash
# Ensure temp directory is writable
chmod 755 /tmp
# Check script permissions
ls -la /tmp/dfirewall_integration_tests/
```

This integration test suite ensures that dfirewall works correctly across all configuration combinations, providing confidence in production deployments with complex configurations.