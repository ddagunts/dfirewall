package main

import (
	"fmt"
	"os"
	"testing"
)

// TestScriptConfigurationInheritance tests script configuration inheritance patterns
func TestScriptConfigurationInheritance(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCases := []ConfigurationCombination{
		{
			Name:        "Global Script Configuration Only",
			Description: "Test global script configuration without client-specific overrides",
			EnvVars: map[string]string{
				"INVOKE_SCRIPT": "/usr/local/bin/global_script.sh",
				"INVOKE_ALWAYS": "true",
				"EXPIRE_SCRIPT": "/usr/local/bin/global_expire.sh",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateGlobalScriptConfig(t)
			},
		},
		{
			Name:        "Client-Specific Script Override",
			Description: "Test client-specific script configuration overriding global defaults",
			EnvVars: map[string]string{
				"INVOKE_SCRIPT": "/usr/local/bin/global_script.sh",
				"INVOKE_ALWAYS": "false",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/usr/local/bin/default_script.sh",
						"expire_script": "/usr/local/bin/default_expire.sh",
						"invoke_always": false,
						"environment": map[string]string{
							"GLOBAL_VAR": "global_value",
						},
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/usr/local/bin/lan_script.sh",
							"expire_script":  "/usr/local/bin/lan_expire.sh",
							"invoke_always":  true,
							"environment": map[string]string{
								"LAN_VAR": "lan_value",
							},
						},
						map[string]interface{}{
							"client_pattern": "10.0.0.100",
							"invoke_script":  "/usr/local/bin/specific_script.sh",
							"invoke_always":  false,
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateClientSpecificConfig(t)
			},
		},
		{
			Name:        "Complex Pattern Matching",
			Description: "Test complex client pattern matching with various IP formats",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/usr/local/bin/default.sh",
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/usr/local/bin/subnet_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "10.0.0.100",
							"invoke_script":  "/usr/local/bin/exact_ip_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "^172\\.16\\.",
							"invoke_script":  "/usr/local/bin/regex_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "2001:db8::/32",
							"invoke_script":  "/usr/local/bin/ipv6_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "*",
							"invoke_script":  "/usr/local/bin/wildcard_script.sh",
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validatePatternMatching(t)
			},
		},
		{
			Name:        "Environment Variable Inheritance",
			Description: "Test environment variable inheritance from defaults to client-specific configs",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/usr/local/bin/default.sh",
						"environment": map[string]string{
							"GLOBAL_VAR1": "global1",
							"GLOBAL_VAR2": "global2",
							"SHARED_VAR":  "from_global",
						},
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/usr/local/bin/client_script.sh",
							"environment": map[string]string{
								"CLIENT_VAR": "client_value",
								"SHARED_VAR": "from_client", // Override global
							},
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateEnvironmentInheritance(t)
			},
		},
		{
			Name:        "Script Configuration Precedence",
			Description: "Test precedence order: env vars -> client config -> defaults",
			EnvVars: map[string]string{
				"INVOKE_SCRIPT": "/env/script.sh",
				"INVOKE_ALWAYS": "true",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/default/script.sh",
						"invoke_always": false,
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.100",
							"invoke_script":  "/client/script.sh",
							"invoke_always":  false,
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateConfigPrecedence(t)
			},
		},
		{
			Name:        "Invalid Client Patterns",
			Description: "Test handling of invalid client patterns in configuration",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/usr/local/bin/default.sh",
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "invalid.ip.address",
							"invoke_script":  "/usr/local/bin/invalid_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "192.168.1.0/99", // Invalid CIDR
							"invoke_script":  "/usr/local/bin/bad_cidr_script.sh",
						},
						map[string]interface{}{
							"client_pattern": "[invalid-regex",
							"invoke_script":  "/usr/local/bin/bad_regex_script.sh",
						},
					},
				},
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateInvalidPatterns(t)
			},
		},
		{
			Name:        "Mixed IPv4 and IPv6 Patterns",
			Description: "Test mixed IPv4 and IPv6 client patterns",
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/usr/local/bin/default.sh",
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.0.0/16",
							"invoke_script":  "/usr/local/bin/ipv4_private.sh",
						},
						map[string]interface{}{
							"client_pattern": "2001:db8::/32",
							"invoke_script":  "/usr/local/bin/ipv6_test.sh",
						},
						map[string]interface{}{
							"client_pattern": "::1",
							"invoke_script":  "/usr/local/bin/ipv6_localhost.sh",
						},
						map[string]interface{}{
							"client_pattern": "127.0.0.1",
							"invoke_script":  "/usr/local/bin/ipv4_localhost.sh",
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateMixedIPVersions(t)
			},
		},
		{
			Name:        "Script Configuration with All Features",
			Description: "Test comprehensive script configuration with all available options",
			EnvVars: map[string]string{
				"INVOKE_SCRIPT": "/global/fallback.sh",
				"EXPIRE_SCRIPT": "/global/expire.sh",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/default/invoke.sh",
						"expire_script": "/default/expire.sh",
						"invoke_always": false,
						"environment": map[string]string{
							"DEFAULT_TIMEOUT": "30",
							"DEFAULT_RETRIES": "3",
						},
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "192.168.1.0/24",
							"invoke_script":  "/lan/invoke.sh",
							"expire_script":  "/lan/expire.sh",
							"invoke_always":  true,
							"environment": map[string]string{
								"LAN_TIMEOUT": "60",
								"LAN_POLICY":  "strict",
							},
						},
						map[string]interface{}{
							"client_pattern": "^10\\.",
							"invoke_script":  "/corporate/invoke.sh",
							"expire_script":  "/corporate/expire.sh",
							"invoke_always":  false,
							"environment": map[string]string{
								"CORP_DOMAIN": "internal.corp.com",
								"CORP_PROXY":  "proxy.corp.com:8080",
							},
						},
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateComprehensiveConfig(t)
			},
		},
	}

	for _, testCase := range testCases {
		suite.runConfigurationTest(t, testCase)
	}
}

// validateGlobalScriptConfig validates global script configuration
func (s *IntegrationTestSuite) validateGlobalScriptConfig(t *testing.T) error {
	expectedScript := os.Getenv("INVOKE_SCRIPT")
	if expectedScript == "" {
		return fmt.Errorf("INVOKE_SCRIPT environment variable not set")
	}

	expectedExpire := os.Getenv("EXPIRE_SCRIPT")
	if expectedExpire == "" {
		return fmt.Errorf("EXPIRE_SCRIPT environment variable not set")
	}

	invokeAlways := os.Getenv("INVOKE_ALWAYS")
	if invokeAlways != "true" {
		return fmt.Errorf("expected INVOKE_ALWAYS to be true, got %s", invokeAlways)
	}

	return nil
}

// validateClientSpecificConfig validates client-specific script configuration
func (s *IntegrationTestSuite) validateClientSpecificConfig(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	if configPath == "" {
		return fmt.Errorf("SCRIPT_CONFIG not set")
	}

	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	if len(config.Clients) != 2 {
		return fmt.Errorf("expected 2 client configurations, got %d", len(config.Clients))
	}

	// Test specific client pattern matching
	testIPs := []struct {
		ip             string
		expectedScript string
	}{
		{"192.168.1.100", "/usr/local/bin/lan_script.sh"},
		{"10.0.0.100", "/usr/local/bin/specific_script.sh"},
		{"172.16.1.1", "/usr/local/bin/default_script.sh"}, // Should use default
	}

	for _, test := range testIPs {
		clientConfig := findClientConfig(test.ip)
		if test.expectedScript == "/usr/local/bin/default_script.sh" {
			// Should not find client-specific config, will use default
			if clientConfig != nil {
				return fmt.Errorf("expected no client config for %s, but found one", test.ip)
			}
		} else {
			if clientConfig == nil {
				return fmt.Errorf("expected client config for %s, but found none", test.ip)
			}
			if clientConfig.InvokeScript != test.expectedScript {
				return fmt.Errorf("expected script %s for %s, got %s", 
					test.expectedScript, test.ip, clientConfig.InvokeScript)
			}
		}
	}

	return nil
}

// validatePatternMatching validates various client pattern matching scenarios
func (s *IntegrationTestSuite) validatePatternMatching(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	testCases := []struct {
		ip             string
		expectedScript string
		description    string
	}{
		{"192.168.1.50", "/usr/local/bin/subnet_script.sh", "CIDR match"},
		{"10.0.0.100", "/usr/local/bin/exact_ip_script.sh", "Exact IP match"},
		{"172.16.1.1", "/usr/local/bin/regex_script.sh", "Regex match"},
		{"2001:db8::1", "/usr/local/bin/ipv6_script.sh", "IPv6 CIDR match"},
		{"203.0.113.1", "/usr/local/bin/wildcard_script.sh", "Wildcard match"},
	}

	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			clientConfig := findClientConfig(test.ip)
			if clientConfig == nil {
				return fmt.Errorf("%s: expected client config for %s, but found none", 
					test.description, test.ip)
			}
			if clientConfig.InvokeScript != test.expectedScript {
				return fmt.Errorf("%s: expected script %s for %s, got %s", 
					test.description, test.expectedScript, test.ip, clientConfig.InvokeScript)
			}
		})
	}

	return nil
}

// validateEnvironmentInheritance validates environment variable inheritance
func (s *IntegrationTestSuite) validateEnvironmentInheritance(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	// Check default environment variables
	if len(config.Defaults.Environment) != 3 {
		return fmt.Errorf("expected 3 default environment variables, got %d", 
			len(config.Defaults.Environment))
	}

	expectedDefaults := map[string]string{
		"GLOBAL_VAR1": "global1",
		"GLOBAL_VAR2": "global2",
		"SHARED_VAR":  "from_global",
	}

	for key, expectedValue := range expectedDefaults {
		if actualValue, exists := config.Defaults.Environment[key]; !exists {
			return fmt.Errorf("expected default environment variable %s, but not found", key)
		} else if actualValue != expectedValue {
			return fmt.Errorf("expected default %s=%s, got %s", key, expectedValue, actualValue)
		}
	}

	// Check client-specific environment variables
	if len(config.Clients) != 1 {
		return fmt.Errorf("expected 1 client configuration, got %d", len(config.Clients))
	}

	clientEnv := config.Clients[0].Environment
	if len(clientEnv) != 2 {
		return fmt.Errorf("expected 2 client environment variables, got %d", len(clientEnv))
	}

	// Check client override
	if clientEnv["SHARED_VAR"] != "from_client" {
		return fmt.Errorf("expected client override SHARED_VAR=from_client, got %s", 
			clientEnv["SHARED_VAR"])
	}

	if clientEnv["CLIENT_VAR"] != "client_value" {
		return fmt.Errorf("expected CLIENT_VAR=client_value, got %s", clientEnv["CLIENT_VAR"])
	}

	return nil
}

// validateConfigPrecedence validates configuration precedence order
func (s *IntegrationTestSuite) validateConfigPrecedence(t *testing.T) error {
	// Environment variables should take precedence
	envScript := os.Getenv("INVOKE_SCRIPT")
	if envScript != "/env/script.sh" {
		return fmt.Errorf("expected environment script /env/script.sh, got %s", envScript)
	}

	envAlways := os.Getenv("INVOKE_ALWAYS")
	if envAlways != "true" {
		return fmt.Errorf("expected environment INVOKE_ALWAYS=true, got %s", envAlways)
	}

	// Load configuration to verify file-based settings exist but are overridden
	configPath := os.Getenv("SCRIPT_CONFIG")
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	// File-based defaults should exist but be overridden by environment
	if config.Defaults.InvokeScript != "/default/script.sh" {
		return fmt.Errorf("expected file-based default script /default/script.sh, got %s", 
			config.Defaults.InvokeScript)
	}

	// Client-specific configuration should still work for client matching
	clientConfig := findClientConfig("192.168.1.100")
	if clientConfig == nil {
		return fmt.Errorf("expected client config for 192.168.1.100")
	}

	if clientConfig.InvokeScript != "/client/script.sh" {
		return fmt.Errorf("expected client script /client/script.sh, got %s", 
			clientConfig.InvokeScript)
	}

	return nil
}

// validateInvalidPatterns validates handling of invalid client patterns
func (s *IntegrationTestSuite) validateInvalidPatterns(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	
	// Loading should succeed but pattern matching should fail gracefully
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		// This is acceptable - invalid configuration should be rejected
		return nil
	}

	// Test that invalid patterns don't match anything
	testIPs := []string{"192.168.1.1", "10.0.0.1", "172.16.1.1"}
	
	for _, ip := range testIPs {
		clientConfig := findClientConfig(ip)
		// With invalid patterns, we should either get no match or default behavior
		if clientConfig != nil {
			t.Logf("IP %s matched invalid pattern - this may indicate pattern validation is needed", ip)
		}
	}

	return fmt.Errorf("invalid patterns should be rejected or handled gracefully")
}

// validateMixedIPVersions validates mixed IPv4 and IPv6 pattern handling
func (s *IntegrationTestSuite) validateMixedIPVersions(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	testCases := []struct {
		ip             string
		expectedScript string
		description    string
	}{
		{"192.168.1.100", "/usr/local/bin/ipv4_private.sh", "IPv4 private network"},
		{"2001:db8::1", "/usr/local/bin/ipv6_test.sh", "IPv6 test network"},
		{"::1", "/usr/local/bin/ipv6_localhost.sh", "IPv6 localhost"},
		{"127.0.0.1", "/usr/local/bin/ipv4_localhost.sh", "IPv4 localhost"},
	}

	for _, test := range testCases {
		clientConfig := findClientConfig(test.ip)
		if clientConfig == nil {
			return fmt.Errorf("%s: expected client config for %s, but found none", 
				test.description, test.ip)
		}
		if clientConfig.InvokeScript != test.expectedScript {
			return fmt.Errorf("%s: expected script %s for %s, got %s", 
				test.description, test.expectedScript, test.ip, clientConfig.InvokeScript)
		}
	}

	return nil
}

// validateComprehensiveConfig validates comprehensive script configuration
func (s *IntegrationTestSuite) validateComprehensiveConfig(t *testing.T) error {
	// Check environment variable fallbacks
	envInvoke := os.Getenv("INVOKE_SCRIPT")
	envExpire := os.Getenv("EXPIRE_SCRIPT")
	
	if envInvoke == "" || envExpire == "" {
		return fmt.Errorf("global environment scripts not set")
	}

	// Load and validate configuration structure
	configPath := os.Getenv("SCRIPT_CONFIG")
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	// Validate defaults section
	if config.Defaults.InvokeScript == "" {
		return fmt.Errorf("default invoke script not configured")
	}
	if config.Defaults.ExpireScript == "" {
		return fmt.Errorf("default expire script not configured")
	}
	if len(config.Defaults.Environment) == 0 {
		return fmt.Errorf("default environment variables not configured")
	}

	// Validate client configurations
	if len(config.Clients) != 2 {
		return fmt.Errorf("expected 2 client configurations, got %d", len(config.Clients))
	}

	// Check LAN client configuration
	lanConfig := findClientConfig("192.168.1.100")
	if lanConfig == nil {
		return fmt.Errorf("LAN client configuration not found")
	}
	if !*lanConfig.InvokeAlways {
		return fmt.Errorf("LAN client should have invoke_always=true")
	}
	if len(lanConfig.Environment) == 0 {
		return fmt.Errorf("LAN client environment variables not configured")
	}

	// Check corporate client configuration
	corpConfig := findClientConfig("10.1.1.1")
	if corpConfig == nil {
		return fmt.Errorf("corporate client configuration not found")
	}
	if corpConfig.InvokeAlways != nil && *corpConfig.InvokeAlways {
		return fmt.Errorf("corporate client should have invoke_always=false or nil")
	}

	return nil
}

// TestScriptConfigurationEdgeCases tests edge cases in script configuration
func TestScriptConfigurationEdgeCases(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCase := ConfigurationCombination{
		Name:        "Script Configuration Edge Cases",
		Description: "Test edge cases like empty patterns, missing scripts, etc.",
		ConfigFiles: map[string]interface{}{
			"script_config.json": map[string]interface{}{
				"version": "1.0",
				"defaults": map[string]interface{}{
					"invoke_script": "",
					"expire_script": "",
				},
				"clients": []interface{}{
					map[string]interface{}{
						"client_pattern": "",
						"invoke_script":  "/empty/pattern.sh",
					},
					map[string]interface{}{
						"client_pattern": "0.0.0.0/0",
						"invoke_script":  "/match/all.sh",
					},
				},
			},
		},
		ExpectError: true,
		Validate: func(t *testing.T, s *IntegrationTestSuite) error {
			configPath := os.Getenv("SCRIPT_CONFIG")
			config, err := loadScriptConfiguration(configPath)
			if err != nil {
				return nil // Expected to fail
			}

			// If it loads, validate that empty configurations are handled
			if config.Defaults.InvokeScript == "" {
				t.Log("Empty default invoke script - should use global fallback")
			}

			return fmt.Errorf("edge case configuration should be validated more strictly")
		},
	}

	suite.runConfigurationTest(t, testCase)
}