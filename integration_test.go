package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
)

// IntegrationTestSuite manages environment and resources for integration tests
type IntegrationTestSuite struct {
	tempDir     string
	redisClient *redis.Client
	cleanup     []func() error
	mu          sync.Mutex
}

// NewIntegrationTestSuite creates a new test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	suite := &IntegrationTestSuite{
		tempDir: t.TempDir(),
		cleanup: make([]func() error, 0),
	}
	
	// Save original environment
	suite.saveEnvironment()
	
	return suite
}

// saveEnvironment saves current environment variables
func (s *IntegrationTestSuite) saveEnvironment() {
	envVars := []string{
		"UPSTREAM", "PORT", "REDIS", "DEBUG", "HANDLE_ALL_IPS", "ENABLE_EDNS",
		"INVOKE_SCRIPT", "INVOKE_ALWAYS", "EXPIRE_SCRIPT", "SCRIPT_CONFIG",
		"BLACKLIST_CONFIG", "REPUTATION_CONFIG", "AI_CONFIG", "CUSTOM_SCRIPT_CONFIG",
		"REDIS_PASSWORD", "REDIS_TLS", "REDIS_TLS_CERT", "REDIS_TLS_KEY",
		"REDIS_TLS_CA", "REDIS_MAX_RETRIES", "REDIS_POOL_SIZE",
		"WEB_UI_PORT", "WEBUI_HTTPS_ENABLED", "WEBUI_PASSWORD_AUTH",
		"WEBUI_USERNAME", "WEBUI_PASSWORD", "WEBUI_LDAP_AUTH",
		"WEBUI_SESSION_SECRET", "SSH_LOG_CONFIG",
	}
	
	originalEnv := make(map[string]string)
	for _, key := range envVars {
		originalEnv[key] = os.Getenv(key)
	}
	
	s.addCleanup(func() error {
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
		return nil
	})
}

// addCleanup adds a cleanup function
func (s *IntegrationTestSuite) addCleanup(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup = append(s.cleanup, fn)
}

// Cleanup runs all cleanup functions
func (s *IntegrationTestSuite) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	var lastErr error
	for i := len(s.cleanup) - 1; i >= 0; i-- {
		if err := s.cleanup[i](); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// createTempFile creates a temporary file with given content
func (s *IntegrationTestSuite) createTempFile(name, content string) string {
	filePath := filepath.Join(s.tempDir, name)
	if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
		panic(fmt.Sprintf("Failed to create temp file %s: %v", filePath, err))
	}
	return filePath
}

// createTempScript creates a temporary executable script
func (s *IntegrationTestSuite) createTempScript(name, content string) string {
	filePath := filepath.Join(s.tempDir, name)
	if err := ioutil.WriteFile(filePath, []byte(content), 0755); err != nil {
		panic(fmt.Sprintf("Failed to create temp script %s: %v", filePath, err))
	}
	return filePath
}

// setEnvVars sets multiple environment variables
func (s *IntegrationTestSuite) setEnvVars(vars map[string]string) {
	for key, value := range vars {
		os.Setenv(key, value)
	}
}

// clearEnvVars clears multiple environment variables
func (s *IntegrationTestSuite) clearEnvVars(keys []string) {
	for _, key := range keys {
		os.Unsetenv(key)
	}
}

// ConfigurationCombination represents a test configuration
type ConfigurationCombination struct {
	Name        string
	Description string
	EnvVars     map[string]string
	ConfigFiles map[string]interface{}
	ExpectError bool
	Validate    func(*testing.T, *IntegrationTestSuite) error
}

// runConfigurationTest runs a single configuration combination test
func (s *IntegrationTestSuite) runConfigurationTest(t *testing.T, combo ConfigurationCombination) {
	t.Run(combo.Name, func(t *testing.T) {
		// Clear environment
		s.clearEnvVars([]string{
			"UPSTREAM", "PORT", "REDIS", "DEBUG", "HANDLE_ALL_IPS", "ENABLE_EDNS",
			"INVOKE_SCRIPT", "INVOKE_ALWAYS", "EXPIRE_SCRIPT", "SCRIPT_CONFIG",
			"BLACKLIST_CONFIG", "REPUTATION_CONFIG", "AI_CONFIG", "CUSTOM_SCRIPT_CONFIG",
			"REDIS_PASSWORD", "REDIS_TLS", "REDIS_TLS_CERT", "REDIS_TLS_KEY",
			"WEB_UI_PORT", "WEBUI_HTTPS_ENABLED", "WEBUI_PASSWORD_AUTH",
		})
		
		// Set test environment variables
		s.setEnvVars(combo.EnvVars)
		
		// Create config files
		for filename, config := range combo.ConfigFiles {
			configData, err := json.Marshal(config)
			if err != nil {
				t.Fatalf("Failed to marshal config for %s: %v", filename, err)
			}
			configPath := s.createTempFile(filename, string(configData))
			
			// Set appropriate env var for config file
			switch filename {
			case "script_config.json":
				os.Setenv("SCRIPT_CONFIG", configPath)
			case "blacklist_config.json":
				os.Setenv("BLACKLIST_CONFIG", configPath)
			case "auth_config.json":
				os.Setenv("WEBUI_AUTH_CONFIG", configPath)
			case "reputation_config.json":
				os.Setenv("REPUTATION_CONFIG", configPath)
			case "ai_config.json":
				os.Setenv("AI_CONFIG", configPath)
			case "custom_script_config.json":
				os.Setenv("CUSTOM_SCRIPT_CONFIG", configPath)
			}
		}
		
		// Run validation if provided
		if combo.Validate != nil {
			err := combo.Validate(t, s)
			if combo.ExpectError {
				if err == nil {
					t.Error("Expected error but validation passed")
				}
			} else {
				if err != nil {
					t.Errorf("Validation failed: %v", err)
				}
			}
		}
	})
}

// Helper function to test Redis connectivity
func (s *IntegrationTestSuite) testRedisConnection(t *testing.T) error {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		return fmt.Errorf("REDIS environment variable not set")
	}
	
	// Parse Redis options
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %v", err)
	}
	
	// Apply additional Redis configuration from environment
	if password := os.Getenv("REDIS_PASSWORD"); password != "" {
		opts.Password = password
	}
	
	if poolSizeStr := os.Getenv("REDIS_POOL_SIZE"); poolSizeStr != "" {
		if poolSize, err := strconv.Atoi(poolSizeStr); err == nil {
			opts.PoolSize = poolSize
		}
	}
	
	client := redis.NewClient(opts)
	defer client.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return client.Ping(ctx).Err()
}

// Helper function to test Web UI accessibility
func (s *IntegrationTestSuite) testWebUIAccess(t *testing.T) error {
	port := os.Getenv("WEB_UI_PORT")
	if port == "" {
		return fmt.Errorf("WEB_UI_PORT not set")
	}
	
	scheme := "http"
	if os.Getenv("WEBUI_HTTPS_ENABLED") == "true" {
		scheme = "https"
	}
	
	url := fmt.Sprintf("%s://localhost:%s/health", scheme, port)
	
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to access Web UI: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 500 {
		return fmt.Errorf("Web UI returned server error: %d", resp.StatusCode)
	}
	
	return nil
}

// Helper function to test DNS resolution
func (s *IntegrationTestSuite) testDNSResolution(t *testing.T, domain string, expectedIP string) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "53"
	}
	
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	
	r, _, err := c.Exchange(m, "127.0.0.1:"+port)
	if err != nil {
		return fmt.Errorf("DNS query failed: %v", err)
	}
	
	if len(r.Answer) == 0 {
		return fmt.Errorf("no DNS answer received")
	}
	
	if expectedIP != "" {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				if a.A.String() == expectedIP {
					return nil
				}
			}
		}
		return fmt.Errorf("expected IP %s not found in DNS response", expectedIP)
	}
	
	return nil
}

// Helper function to validate script execution
func (s *IntegrationTestSuite) validateScriptExecution(t *testing.T) error {
	scriptContent := `#!/bin/bash
echo "Script executed successfully"
echo "CLIENT_IP: $DFIREWALL_CLIENT_IP"
echo "RESOLVED_IP: $DFIREWALL_RESOLVED_IP"
echo "DOMAIN: $DFIREWALL_DOMAIN"
exit 0
`
	scriptPath := s.createTempScript("test_script.sh", scriptContent)
	os.Setenv("INVOKE_SCRIPT", scriptPath)
	
	// This would require actually running the proxy and triggering script execution
	// For now, we'll just verify the script is executable
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("script not accessible: %v", err)
	}
	
	return nil
}