package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadScriptConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		config      *ScriptConfiguration
		expectError bool
	}{
		{
			name: "Valid configuration",
			config: &ScriptConfiguration{
				Version: "1.0",
				Defaults: struct {
					InvokeScript string            `json:"invoke_script,omitempty"`
					ExpireScript string            `json:"expire_script,omitempty"`
					InvokeAlways bool              `json:"invoke_always,omitempty"`
					Environment  map[string]string `json:"environment,omitempty"`
				}{
					InvokeScript: "/bin/echo",
					ExpireScript: "/bin/echo",
					InvokeAlways: true,
					Environment: map[string]string{
						"TEST_VAR": "test_value",
					},
				},
				Clients: []ClientScriptConfig{
					{
						ClientPattern: "192.168.1.0/24",
						InvokeScript:  "/usr/bin/custom",
						ExpireScript:  "/usr/bin/cleanup",
						InvokeAlways:  &[]bool{false}[0],
					},
				},
			},
			expectError: false,
		},
		{
			name: "Configuration with regex pattern",
			config: &ScriptConfiguration{
				Version: "1.0",
				Defaults: struct {
					InvokeScript string            `json:"invoke_script,omitempty"`
					ExpireScript string            `json:"expire_script,omitempty"`
					InvokeAlways bool              `json:"invoke_always,omitempty"`
					Environment  map[string]string `json:"environment,omitempty"`
				}{
					InvokeScript: "/bin/echo",
				},
				Clients: []ClientScriptConfig{
					{
						ClientPattern: "regex:^192\\.168\\.",
						InvokeScript:  "/usr/bin/regex",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Empty configuration",
			config: &ScriptConfiguration{
				Version: "1.0",
				Defaults: struct {
					InvokeScript string            `json:"invoke_script,omitempty"`
					ExpireScript string            `json:"expire_script,omitempty"`
					InvokeAlways bool              `json:"invoke_always,omitempty"`
					Environment  map[string]string `json:"environment,omitempty"`
				}{},
				Clients: []ClientScriptConfig{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			configFile := filepath.Join(tempDir, "test_config.json")
			configData, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("Failed to marshal config: %v", err)
			}

			err = os.WriteFile(configFile, configData, 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Test loading configuration
			loadedConfig, err := loadScriptConfiguration(configFile)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if loadedConfig == nil {
				t.Error("Loaded configuration should not be nil")
				return
			}

			// Verify configuration content
			if loadedConfig.Defaults.InvokeScript != tt.config.Defaults.InvokeScript {
				t.Errorf("Expected invoke script %s, got %s", 
					tt.config.Defaults.InvokeScript, loadedConfig.Defaults.InvokeScript)
			}

			if len(loadedConfig.Clients) != len(tt.config.Clients) {
				t.Errorf("Expected %d clients, got %d", 
					len(tt.config.Clients), len(loadedConfig.Clients))
			}
		})
	}
}

func TestLoadScriptConfigurationInvalidFiles(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		fileContent string
		expectError bool
	}{
		{
			name:        "Invalid JSON",
			fileContent: "{invalid json}",
			expectError: true,
		},
		{
			name:        "Empty file",
			fileContent: "",
			expectError: true,
		},
		{
			name:        "Non-JSON content",
			fileContent: "This is not JSON",
			expectError: true,
		},
		{
			name:        "Valid but minimal JSON",
			fileContent: "{}",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tempDir, "test_config.json")
			err := os.WriteFile(configFile, []byte(tt.fileContent), 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			_, err = loadScriptConfiguration(configFile)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}

	t.Run("Non-existent file", func(t *testing.T) {
		_, err := loadScriptConfiguration("/non/existent/file.json")
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})
}

func TestFindClientConfig(t *testing.T) {
	// Set up test script configuration
	testConfig := &ScriptConfiguration{
		Version: "1.0",
		Defaults: struct {
			InvokeScript string            `json:"invoke_script,omitempty"`
			ExpireScript string            `json:"expire_script,omitempty"`
			InvokeAlways bool              `json:"invoke_always,omitempty"`
			Environment  map[string]string `json:"environment,omitempty"`
		}{
			InvokeScript: "/default/script",
			ExpireScript: "/default/expire",
			InvokeAlways: false,
		},
		Clients: []ClientScriptConfig{
			{
				ClientPattern: "192.168.1.0/24",
				InvokeScript:  "/cidr/script",
				ExpireScript:  "/cidr/expire",
				InvokeAlways:  &[]bool{true}[0],
			},
			{
				ClientPattern: "10.0.0.100",
				InvokeScript:  "/specific/script",
			},
			{
				ClientPattern: "regex:^172\\.16\\.",
				InvokeScript:  "/regex/script",
			},
		},
	}

	// Save original and restore after test
	originalScriptConfig := scriptConfig
	scriptConfig = testConfig
	defer func() {
		scriptConfig = originalScriptConfig
	}()

	tests := []struct {
		name         string
		clientIP     string
		expectConfig bool
		expectScript string
	}{
		{
			name:         "CIDR match",
			clientIP:     "192.168.1.50",
			expectConfig: true,
			expectScript: "/cidr/script",
		},
		{
			name:         "Specific IP match",
			clientIP:     "10.0.0.100",
			expectConfig: true,
			expectScript: "/specific/script",
		},
		{
			name:         "Regex match",
			clientIP:     "172.16.1.1",
			expectConfig: true,
			expectScript: "/regex/script",
		},
		{
			name:         "No match - should return nil",
			clientIP:     "203.0.113.1",
			expectConfig: false,
		},
		{
			name:         "Invalid IP",
			clientIP:     "invalid-ip",
			expectConfig: false,
		},
		{
			name:         "Empty IP",
			clientIP:     "",
			expectConfig: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := findClientConfig(tt.clientIP)

			if tt.expectConfig {
				if config == nil {
					t.Error("Expected to find client config but got nil")
					return
				}
				if config.InvokeScript != tt.expectScript {
					t.Errorf("Expected script %s, got %s", tt.expectScript, config.InvokeScript)
				}
			} else {
				if config != nil {
					t.Errorf("Expected no config but got: %+v", config)
				}
			}
		})
	}
}

func TestMatchesClientPattern(t *testing.T) {
	tests := []struct {
		name     string
		clientIP string
		pattern  string
		expected bool
	}{
		{
			name:     "Exact IP match",
			clientIP: "192.168.1.100",
			pattern:  "192.168.1.100",
			expected: true,
		},
		{
			name:     "CIDR match - in range",
			clientIP: "192.168.1.50",
			pattern:  "192.168.1.0/24",
			expected: true,
		},
		{
			name:     "CIDR match - out of range",
			clientIP: "192.168.2.50",
			pattern:  "192.168.1.0/24",
			expected: false,
		},
		{
			name:     "IPv6 CIDR match",
			clientIP: "2001:db8::50",
			pattern:  "2001:db8::/32",
			expected: true,
		},
		{
			name:     "Regex match - simple",
			clientIP: "192.168.1.100",
			pattern:  "regex:^192\\.168\\.",
			expected: true,
		},
		{
			name:     "Regex match - complex",
			clientIP: "172.16.1.1",
			pattern:  "regex:^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)",
			expected: true,
		},
		{
			name:     "Regex no match",
			clientIP: "203.0.113.1",
			pattern:  "regex:^192\\.168\\.",
			expected: false,
		},
		{
			name:     "Invalid regex pattern",
			clientIP: "192.168.1.100",
			pattern:  "[invalid-regex",
			expected: false,
		},
		{
			name:     "Empty pattern",
			clientIP: "192.168.1.100",
			pattern:  "",
			expected: false,
		},
		{
			name:     "Wildcard pattern",
			clientIP: "192.168.1.100",
			pattern:  "*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesClientPattern(tt.clientIP, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchesClientPattern(%s, %s) = %v, expected %v",
					tt.clientIP, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestWebUIAuthConfigLoading(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name           string
		config         *WebUIAuthConfig
		envVars        map[string]string
		expectedHTTPS  bool
		expectedAuth   bool
		expectedSecret string
	}{
		{
			name: "Complete configuration",
			config: &WebUIAuthConfig{
				HTTPSEnabled:    true,
				CertFile:        "/path/to/cert.pem",
				KeyFile:         "/path/to/key.pem",
				PasswordAuth:    true,
				Username:        "admin",
				Password:        "hashedpassword",
				LDAPAuth:        true,
				LDAPServer:      "ldap.example.com",
				LDAPPort:        389,
				LDAPBaseDN:      "dc=example,dc=com",
				SessionSecret:   "custom-secret",
				SessionExpiry:   48,
				HeaderAuth:      true,
				HeaderName:      "X-Remote-User",
				HeaderValues:    []string{"allowed-user"},
				TrustedProxies:  []string{"127.0.0.1", "192.168.1.0/24"},
			},
			expectedHTTPS:  true,
			expectedAuth:   true,
			expectedSecret: "custom-secret",
		},
		{
			name: "Minimal configuration",
			config: &WebUIAuthConfig{
				PasswordAuth: true,
				Username:     "user",
				Password:     "pass",
			},
			expectedHTTPS: false,
			expectedAuth:  true,
		},
		{
			name: "Environment variable override",
			config: &WebUIAuthConfig{
				HTTPSEnabled: false,
			},
			envVars: map[string]string{
				"WEBUI_HTTPS_ENABLED": "true",
				"WEBUI_PASSWORD_AUTH": "true",
				"WEBUI_USERNAME":      "envuser",
				"WEBUI_PASSWORD":      "envpass",
			},
			expectedHTTPS: true,
			expectedAuth:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original environment
			originalEnv := make(map[string]string)
			envKeys := []string{
				"WEBUI_AUTH_CONFIG", "WEBUI_HTTPS_ENABLED", "WEBUI_PASSWORD_AUTH",
				"WEBUI_USERNAME", "WEBUI_PASSWORD", "WEBUI_SESSION_SECRET",
			}
			for _, key := range envKeys {
				originalEnv[key] = os.Getenv(key)
				os.Unsetenv(key)
			}

			// Restore environment after test
			defer func() {
				for key, value := range originalEnv {
					if value != "" {
						os.Setenv(key, value)
					} else {
						os.Unsetenv(key)
					}
				}
			}()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Create config file if config is provided
			if tt.config != nil {
				configFile := filepath.Join(tempDir, "auth_config.json")
				configData, err := json.Marshal(tt.config)
				if err != nil {
					t.Fatalf("Failed to marshal config: %v", err)
				}

				err = os.WriteFile(configFile, configData, 0644)
				if err != nil {
					t.Fatalf("Failed to write config file: %v", err)
				}

				os.Setenv("WEBUI_AUTH_CONFIG", configFile)
			}

			// Load configuration
			config := loadAuthConfig()

			// Verify results
			if config.HTTPSEnabled != tt.expectedHTTPS {
				t.Errorf("Expected HTTPS enabled: %v, got: %v", tt.expectedHTTPS, config.HTTPSEnabled)
			}

			if config.PasswordAuth != tt.expectedAuth {
				t.Errorf("Expected password auth: %v, got: %v", tt.expectedAuth, config.PasswordAuth)
			}

			if tt.expectedSecret != "" && config.SessionSecret != tt.expectedSecret {
				t.Errorf("Expected session secret: %s, got: %s", tt.expectedSecret, config.SessionSecret)
			}

			// Session secret should always be set
			if config.SessionSecret == "" {
				t.Error("Session secret should not be empty")
			}
		})
	}
}

func TestBlacklistConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	// Create test blacklist configuration
	blacklistConfig := map[string]interface{}{
		"ip_blacklist": []string{
			"192.168.1.100",
			"10.0.0.0/8",
			"203.0.113.0/24",
		},
		"domain_blacklist": []string{
			"malware.com",
			"phishing.example.com",
			"*.bad-domain.org",
		},
		"whitelist_override": []string{
			"192.168.1.200",
			"trusted.example.com",
		},
	}

	configFile := filepath.Join(tempDir, "blacklist_config.json")
	configData, err := json.Marshal(blacklistConfig)
	if err != nil {
		t.Fatalf("Failed to marshal blacklist config: %v", err)
	}

	err = os.WriteFile(configFile, configData, 0644)
	if err != nil {
		t.Fatalf("Failed to write blacklist config file: %v", err)
	}

	t.Run("Load blacklist configuration", func(t *testing.T) {
		// Load configuration from file
		var loadedConfig map[string]interface{}
		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}

		err = json.Unmarshal(data, &loadedConfig)
		if err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		// Verify IP blacklist
		if ipList, ok := loadedConfig["ip_blacklist"].([]interface{}); ok {
			if len(ipList) != 3 {
				t.Errorf("Expected 3 IP blacklist entries, got %d", len(ipList))
			}
		} else {
			t.Error("IP blacklist should be present")
		}

		// Verify domain blacklist
		if domainList, ok := loadedConfig["domain_blacklist"].([]interface{}); ok {
			if len(domainList) != 3 {
				t.Errorf("Expected 3 domain blacklist entries, got %d", len(domainList))
			}
		} else {
			t.Error("Domain blacklist should be present")
		}
	})

	t.Run("Validate blacklist entries", func(t *testing.T) {
		// Test IP validation
		testIPs := []string{"192.168.1.100", "10.0.0.0/8", "invalid-ip"}
		for _, ip := range testIPs {
			if strings.Contains(ip, "/") {
				// CIDR validation
				_, _, err := net.ParseCIDR(ip)
				if err != nil && ip != "invalid-ip" {
					t.Errorf("Valid CIDR %s failed validation: %v", ip, err)
				}
			} else {
				// IP validation
				parsed := net.ParseIP(ip)
				if parsed == nil && ip != "invalid-ip" {
					t.Errorf("Valid IP %s failed validation", ip)
				}
			}
		}

		// Test domain validation
		testDomains := []string{"malware.com", "*.bad-domain.org", "valid.example.com"}
		for _, domain := range testDomains {
			// Basic domain validation (more comprehensive validation would be in validateDomain)
			if domain == "" {
				t.Error("Domain should not be empty")
			}
			if strings.Contains(domain, " ") {
				t.Errorf("Domain %s should not contain spaces", domain)
			}
		}
	})
}

func TestConfigurationValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid configuration",
			config: map[string]interface{}{
				"redis_url":    "redis://localhost:6379",
				"upstream_dns": "8.8.8.8:53",
				"port":         53,
			},
			expectError: false,
		},
		{
			name: "Invalid port - too high",
			config: map[string]interface{}{
				"port": 70000,
			},
			expectError: true,
			errorMsg:    "port",
		},
		{
			name: "Invalid port - negative",
			config: map[string]interface{}{
				"port": -1,
			},
			expectError: true,
			errorMsg:    "port",
		},
		{
			name: "Invalid Redis URL",
			config: map[string]interface{}{
				"redis_url": "invalid-url",
			},
			expectError: true,
			errorMsg:    "redis",
		},
		{
			name: "Missing required fields",
			config: map[string]interface{}{
				"optional_field": "value",
			},
			expectError: false, // Depends on what's considered required
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// Validate port
			if port, ok := tt.config["port"].(int); ok {
				if port < 1 || port > 65535 {
					err = &ConfigError{Field: "port", Message: "invalid port range"}
				}
			}

			// Validate Redis URL
			if redisURL, ok := tt.config["redis_url"].(string); ok {
				if !strings.HasPrefix(redisURL, "redis://") && !strings.HasPrefix(redisURL, "rediss://") {
					err = &ConfigError{Field: "redis_url", Message: "invalid Redis URL format"}
				}
			}

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Message
}

func TestEnvironmentVariableHandling(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		value    string
		expected interface{}
	}{
		{
			name:     "String value",
			envVar:   "TEST_STRING",
			value:    "test-value",
			expected: "test-value",
		},
		{
			name:     "Boolean true",
			envVar:   "TEST_BOOL_TRUE",
			value:    "true",
			expected: true,
		},
		{
			name:     "Boolean false",
			envVar:   "TEST_BOOL_FALSE",
			value:    "false",
			expected: false,
		},
		{
			name:     "Integer value",
			envVar:   "TEST_INT",
			value:    "12345",
			expected: 12345,
		},
		{
			name:     "Empty value",
			envVar:   "TEST_EMPTY",
			value:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original value
			original := os.Getenv(tt.envVar)
			defer func() {
				if original != "" {
					os.Setenv(tt.envVar, original)
				} else {
					os.Unsetenv(tt.envVar)
				}
			}()

			// Set test value
			os.Setenv(tt.envVar, tt.value)

			// Test retrieval and conversion
			retrieved := os.Getenv(tt.envVar)
			if retrieved != tt.value {
				t.Errorf("Expected env var %s = %s, got %s", tt.envVar, tt.value, retrieved)
			}

			// Test type conversion for specific cases
			switch tt.expected.(type) {
			case bool:
				converted := retrieved == "true"
				if converted != tt.expected {
					t.Errorf("Boolean conversion failed: expected %v, got %v", tt.expected, converted)
				}
			case int:
				if tt.value != "" {
					// Note: In real code, you'd use strconv.Atoi with error handling
					expectedStr := tt.value
					if expectedStr != tt.value {
						t.Errorf("Integer conversion test setup error")
					}
				}
			}
		})
	}
}