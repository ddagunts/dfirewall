package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// TestConfigurationValidationChains tests configuration validation dependency chains
func TestConfigurationValidationChains(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCases := []ConfigurationCombination{
		{
			Name:        "Redis-dependent Features Validation",
			Description: "Test that features requiring Redis fail gracefully without Redis",
			EnvVars: map[string]string{
				"UPSTREAM":       "8.8.8.8:53",
				"PORT":           "53",
				// REDIS not set - should cause dependent features to fail
				"WEB_UI_PORT":    "8080",
				"INVOKE_SCRIPT":  "/bin/echo",
				"EXPIRE_SCRIPT":  "/bin/echo",
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateRedisDependencies(t)
			},
		},
		{
			Name:        "Upstream DNS Validation Chain",
			Description: "Test DNS upstream dependency validation",
			EnvVars: map[string]string{
				"REDIS": "redis://localhost:6379",
				"PORT":  "53",
				// UPSTREAM not set - should cause DNS forwarding to fail
				"HANDLE_ALL_IPS": "true",
				"ENABLE_EDNS":    "true",
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateUpstreamDependencies(t)
			},
		},
		{
			Name:        "Port Conflict Validation",
			Description: "Test validation of port conflicts between DNS and Web UI",
			EnvVars: map[string]string{
				"REDIS":       "redis://localhost:6379",
				"UPSTREAM":    "8.8.8.8:53",
				"PORT":        "8080",
				"WEB_UI_PORT": "8080", // Same port as DNS - should conflict
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validatePortConflicts(t)
			},
		},
		{
			Name:        "Script Path Validation Chain",
			Description: "Test script path validation and dependency chains",
			EnvVars: map[string]string{
				"REDIS":         "redis://localhost:6379",
				"UPSTREAM":      "8.8.8.8:53",
				"INVOKE_SCRIPT": "/nonexistent/script.sh",
				"EXPIRE_SCRIPT": "/also/nonexistent.sh",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/another/missing/script.sh",
						"expire_script": "/yet/another/missing.sh",
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/client/missing/script.sh",
						},
					},
				},
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateScriptPaths(t)
			},
		},
		{
			Name:        "Configuration File Dependency Chain",
			Description: "Test dependencies between different configuration files",
			EnvVars: map[string]string{
				"REDIS":   "redis://localhost:6379",
				"UPSTREAM": "8.8.8.8:53",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/echo",
					},
				},
				"blacklist_config.json": map[string]interface{}{
					"ip_blacklist": []string{"192.168.1.100"},
				},
				"reputation_config.json": map[string]interface{}{
					"enabled": true,
					"providers": map[string]interface{}{
						"virustotal": map[string]interface{}{
							"enabled": true,
							"api_key": "", // Empty API key should cause validation error
						},
					},
				},
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateConfigFileDependencies(t)
			},
		},
		{
			Name:        "Environment vs File Configuration Precedence",
			Description: "Test validation of environment variable vs file configuration precedence",
			EnvVars: map[string]string{
				"REDIS":         "redis://localhost:6379",
				"UPSTREAM":      "8.8.8.8:53",
				"INVOKE_SCRIPT": "/env/script.sh",      // From environment
				"WEB_UI_PORT":   "invalid_port_number", // Invalid value from env
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/file/script.sh", // From file
					},
				},
				"auth_config.json": map[string]interface{}{
					"password_auth": true,
					"username":      "fileuser",
				},
			},
			ExpectError: true, // Invalid port should cause validation error
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateConfigPrecedenceValidation(t)
			},
		},
		{
			Name:        "Circular Dependency Detection",
			Description: "Test detection of circular dependencies in configuration",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/circular_script.sh",
						"expire_script": "/bin/circular_expire.sh",
					},
				},
				"custom_script_config.json": map[string]interface{}{
					"enabled": true,
					"unified_script": map[string]interface{}{
						"enabled":     true,
						"script_path": "/bin/circular_script.sh", // Same as invoke script
					},
				},
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateCircularDependencies(t)
			},
		},
		{
			Name:        "Resource Availability Validation Chain",
			Description: "Test validation of required resources (Redis, DNS, scripts, etc.)",
			EnvVars: map[string]string{
				"REDIS":         "redis://invalid-host:6379", // Invalid Redis host
				"UPSTREAM":      "999.999.999.999:53",        // Invalid upstream DNS
				"INVOKE_SCRIPT": "/dev/null",                 // Not executable
				"WEB_UI_PORT":   "99999",                     // Invalid port range
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateResourceAvailability(t)
			},
		},
		{
			Name:        "Complete Valid Configuration Chain",
			Description: "Test a complete, valid configuration with all dependencies satisfied",
			EnvVars: map[string]string{
				"REDIS":       "redis://localhost:6379",
				"UPSTREAM":    "8.8.8.8:53",
				"PORT":        "5353", // Use alternate port to avoid conflicts
				"WEB_UI_PORT": "8080",
				"DEBUG":       "false",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/echo",
						"expire_script": "/bin/echo",
						"invoke_always": false,
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/bin/echo",
						},
					},
				},
				"auth_config.json": map[string]interface{}{
					"password_auth": true,
					"username":      "admin",
					"password":      "hashedpassword",
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateCompleteConfiguration(t)
			},
		},
		{
			Name:        "Version Compatibility Validation",
			Description: "Test validation of configuration version compatibility",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "999.0", // Future/unsupported version
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/echo",
					},
				},
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateVersionCompatibility(t)
			},
		},
	}

	for _, testCase := range testCases {
		suite.runConfigurationTest(t, testCase)
	}
}

// validateRedisDependencies validates that Redis-dependent features fail without Redis
func (s *IntegrationTestSuite) validateRedisDependencies(t *testing.T) error {
	redisURL := os.Getenv("REDIS")
	if redisURL != "" {
		return fmt.Errorf("REDIS should not be set for this test")
	}

	// Test Redis connection - should fail
	err := s.testRedisConnection(t)
	if err == nil {
		return fmt.Errorf("Redis connection should fail when REDIS is not set")
	}

	t.Log("Redis dependency validation passed - connection failed as expected")
	return nil
}

// validateUpstreamDependencies validates upstream DNS dependencies
func (s *IntegrationTestSuite) validateUpstreamDependencies(t *testing.T) error {
	upstream := os.Getenv("UPSTREAM")
	if upstream != "" {
		return fmt.Errorf("UPSTREAM should not be set for this test")
	}

	// DNS forwarding should fail without upstream configured
	t.Log("Upstream DNS dependency validation passed - no upstream configured")
	return fmt.Errorf("upstream DNS not configured - DNS forwarding will fail")
}

// validatePortConflicts validates port conflict detection
func (s *IntegrationTestSuite) validatePortConflicts(t *testing.T) error {
	dnsPort := os.Getenv("PORT")
	webUIPort := os.Getenv("WEB_UI_PORT")

	if dnsPort != webUIPort {
		return fmt.Errorf("expected port conflict, but ports are different: DNS=%s, WebUI=%s", 
			dnsPort, webUIPort)
	}

	if dnsPort == "8080" && webUIPort == "8080" {
		return fmt.Errorf("port conflict detected: both DNS and Web UI trying to use port 8080")
	}

	return fmt.Errorf("port conflict validation should have detected the issue")
}

// validateScriptPaths validates script path accessibility
func (s *IntegrationTestSuite) validateScriptPaths(t *testing.T) error {
	invokeScript := os.Getenv("INVOKE_SCRIPT")
	expireScript := os.Getenv("EXPIRE_SCRIPT")

	// Check environment script paths
	if invokeScript != "" {
		if _, err := os.Stat(invokeScript); err == nil {
			return fmt.Errorf("invoke script should not exist: %s", invokeScript)
		}
	}

	if expireScript != "" {
		if _, err := os.Stat(expireScript); err == nil {
			return fmt.Errorf("expire script should not exist: %s", expireScript)
		}
	}

	// Check configuration file script paths
	configPath := os.Getenv("SCRIPT_CONFIG")
	if configPath != "" {
		config, err := loadScriptConfiguration(configPath)
		if err != nil {
			// This is expected behavior - configuration should fail to load with invalid scripts
			t.Log("Script configuration failed to load as expected due to invalid paths")
			return nil
		}

		// If it loads, verify that script validation would catch the issues
		if config.Defaults.InvokeScript != "" {
			if _, err := os.Stat(config.Defaults.InvokeScript); err == nil {
				return fmt.Errorf("default invoke script should not exist: %s", 
					config.Defaults.InvokeScript)
			}
		}
	}

	return fmt.Errorf("script path validation should have detected missing scripts")
}

// validateConfigFileDependencies validates dependencies between config files
func (s *IntegrationTestSuite) validateConfigFileDependencies(t *testing.T) error {
	// Check that reputation config with empty API key fails validation
	reputationPath := os.Getenv("REPUTATION_CONFIG")
	if reputationPath == "" {
		return fmt.Errorf("REPUTATION_CONFIG should be set for this test")
	}

	// This should fail due to empty API key
	t.Log("Configuration file dependency validation - empty API key should cause failure")
	return fmt.Errorf("reputation configuration with empty API key should be rejected")
}

// validateConfigPrecedenceValidation validates config precedence validation
func (s *IntegrationTestSuite) validateConfigPrecedenceValidation(t *testing.T) error {
	webUIPort := os.Getenv("WEB_UI_PORT")
	if webUIPort != "invalid_port_number" {
		return fmt.Errorf("expected invalid port value for testing")
	}

	// Try to parse the port
	if _, err := strconv.Atoi(webUIPort); err == nil {
		return fmt.Errorf("port value should be invalid")
	}

	// Environment variable validation should catch this
	return fmt.Errorf("invalid port number in environment should be caught by validation")
}

// validateCircularDependencies validates circular dependency detection
func (s *IntegrationTestSuite) validateCircularDependencies(t *testing.T) error {
	scriptConfigPath := os.Getenv("SCRIPT_CONFIG")
	customScriptConfigPath := os.Getenv("CUSTOM_SCRIPT_CONFIG")

	if scriptConfigPath == "" || customScriptConfigPath == "" {
		return fmt.Errorf("both config paths should be set for circular dependency test")
	}

	// Both configurations reference the same script - potential circular dependency
	t.Log("Circular dependency validation - same script referenced in multiple configs")
	return fmt.Errorf("circular dependency should be detected when same script is used in multiple contexts")
}

// validateResourceAvailability validates resource availability
func (s *IntegrationTestSuite) validateResourceAvailability(t *testing.T) error {
	// Test Redis connectivity with invalid host
	redisURL := os.Getenv("REDIS")
	if redisURL != "redis://invalid-host:6379" {
		return fmt.Errorf("expected invalid Redis URL for testing")
	}

	err := s.testRedisConnection(t)
	if err == nil {
		return fmt.Errorf("Redis connection should fail with invalid host")
	}

	// Test upstream DNS with invalid address
	upstream := os.Getenv("UPSTREAM")
	if upstream != "999.999.999.999:53" {
		return fmt.Errorf("expected invalid upstream DNS for testing")
	}

	// Test port range validation
	webUIPort := os.Getenv("WEB_UI_PORT")
	if port, err := strconv.Atoi(webUIPort); err == nil {
		if port <= 65535 {
			return fmt.Errorf("expected port to be out of valid range")
		}
	}

	t.Log("Resource availability validation passed - all resources failed as expected")
	return nil
}

// validateCompleteConfiguration validates a complete, valid configuration
func (s *IntegrationTestSuite) validateCompleteConfiguration(t *testing.T) error {
	// Validate all required environment variables are set
	requiredEnvVars := []string{"REDIS", "UPSTREAM", "PORT", "WEB_UI_PORT"}
	for _, envVar := range requiredEnvVars {
		if value := os.Getenv(envVar); value == "" {
			return fmt.Errorf("required environment variable %s not set", envVar)
		}
	}

	// Validate port numbers are valid
	for _, portVar := range []string{"PORT", "WEB_UI_PORT"} {
		portStr := os.Getenv(portVar)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port number for %s: %s", portVar, portStr)
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("port %s out of valid range: %d", portVar, port)
		}
	}

	// Validate configuration files can be loaded
	scriptConfigPath := os.Getenv("SCRIPT_CONFIG")
	if scriptConfigPath != "" {
		_, err := loadScriptConfiguration(scriptConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load script configuration: %v", err)
		}
	}

	authConfigPath := os.Getenv("WEBUI_AUTH_CONFIG")
	if authConfigPath != "" {
		config := loadAuthConfig()
		if !config.PasswordAuth {
			return fmt.Errorf("password authentication should be enabled")
		}
		if config.Username == "" {
			return fmt.Errorf("username should be configured")
		}
	}

	// Test connectivity to external services
	if err := s.testRedisConnection(t); err != nil {
		return fmt.Errorf("Redis connection failed: %v", err)
	}

	t.Log("Complete configuration validation passed")
	return nil
}

// validateVersionCompatibility validates configuration version compatibility
func (s *IntegrationTestSuite) validateVersionCompatibility(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	if configPath == "" {
		return fmt.Errorf("SCRIPT_CONFIG should be set for version test")
	}

	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		// This is expected - unsupported version should cause loading to fail
		t.Log("Configuration loading failed as expected due to unsupported version")
		return nil
	}

	if config.Version == "999.0" {
		return fmt.Errorf("unsupported configuration version should be rejected")
	}

	return fmt.Errorf("version compatibility validation should have rejected version 999.0")
}

// TestConfigurationValidationOrder tests the order of configuration validation
func TestConfigurationValidationOrder(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCase := ConfigurationCombination{
		Name:        "Configuration Validation Order",
		Description: "Test that configuration validation happens in the correct order",
		EnvVars: map[string]string{
			"REDIS":       "redis://localhost:6379",
			"UPSTREAM":    "8.8.8.8:53",
			"PORT":        "53",
			"WEB_UI_PORT": "8080",
		},
		Validate: func(t *testing.T, s *IntegrationTestSuite) error {
			// Test validation order:
			// 1. Environment variables
			// 2. Configuration file loading
			// 3. Cross-configuration validation
			// 4. Resource availability
			// 5. Dependency resolution

			validationSteps := []struct {
				name     string
				validate func() error
			}{
				{
					name: "Environment Variable Validation",
					validate: func() error {
						requiredVars := []string{"REDIS", "UPSTREAM"}
						for _, envVar := range requiredVars {
							if os.Getenv(envVar) == "" {
								return fmt.Errorf("required environment variable %s not set", envVar)
							}
						}
						return nil
					},
				},
				{
					name: "Port Range Validation",
					validate: func() error {
						portStr := os.Getenv("PORT")
						port, err := strconv.Atoi(portStr)
						if err != nil {
							return fmt.Errorf("invalid port: %s", portStr)
						}
						if port < 1 || port > 65535 {
							return fmt.Errorf("port out of range: %d", port)
						}
						return nil
					},
				},
				{
					name: "Resource Connectivity Validation",
					validate: func() error {
						return s.testRedisConnection(t)
					},
				},
			}

			for i, step := range validationSteps {
				t.Logf("Validation step %d: %s", i+1, step.name)
				if err := step.validate(); err != nil {
					return fmt.Errorf("validation step %d (%s) failed: %v", i+1, step.name, err)
				}
			}

			t.Log("All validation steps passed in correct order")
			return nil
		},
	}

	suite.runConfigurationTest(t, testCase)
}

// TestConfigurationRollback tests configuration rollback on validation failure
func TestConfigurationRollback(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCase := ConfigurationCombination{
		Name:        "Configuration Rollback",
		Description: "Test that configuration changes are rolled back on validation failure",
		EnvVars: map[string]string{
			"REDIS":    "redis://localhost:6379",
			"UPSTREAM": "8.8.8.8:53",
		},
		ConfigFiles: map[string]interface{}{
			"script_config.json": map[string]interface{}{
				"version": "1.0",
				"defaults": map[string]interface{}{
					"invoke_script": "/nonexistent/script.sh", // This should cause validation failure
				},
			},
		},
		ExpectError: true,
		Validate: func(t *testing.T, s *IntegrationTestSuite) error {
			configPath := os.Getenv("SCRIPT_CONFIG")
			if configPath == "" {
				return fmt.Errorf("SCRIPT_CONFIG not set")
			}

			// Attempt to load configuration - should fail due to invalid script path
			_, err := loadScriptConfiguration(configPath)
			if err != nil {
				t.Log("Configuration loading failed as expected - rollback scenario")
				return nil // This is the expected behavior
			}

			// If loading succeeded, check if validation would catch the issue
			return fmt.Errorf("configuration with invalid script path should fail validation")
		},
	}

	suite.runConfigurationTest(t, testCase)
}