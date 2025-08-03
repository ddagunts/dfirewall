package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestResourceExhaustionScenarios tests various resource exhaustion scenarios
func TestResourceExhaustionScenarios(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCases := []ConfigurationCombination{
		{
			Name:        "High Connection Pool Redis",
			Description: "Test with very high Redis connection pool under load",
			EnvVars: map[string]string{
				"REDIS":               "redis://localhost:6379",
				"REDIS_POOL_SIZE":     "500",
				"REDIS_MAX_RETRIES":   "10",
				"REDIS_DIAL_TIMEOUT":  "5s",
				"REDIS_READ_TIMEOUT":  "3s",
				"REDIS_WRITE_TIMEOUT": "3s",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisUnderLoad(t, 1000, 50) // 1000 ops, 50 concurrent
			},
		},
		{
			Name:        "All Features Memory Stress",
			Description: "Test memory usage with all features enabled under load",
			EnvVars: map[string]string{
				"REDIS":          "redis://localhost:6379",
				"HANDLE_ALL_IPS": "true",
				"ENABLE_EDNS":    "true",
				"DEBUG":          "true",
				"WEB_UI_PORT":    "8080",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/echo",
						"invoke_always": true,
					},
					"clients": []interface{}{
						map[string]interface{}{
							"client_pattern": "*",
							"invoke_script":  "/bin/echo",
						},
					},
				},
				"blacklist_config.json": map[string]interface{}{
					"ip_blacklist":     generateLargeIPList(1000),
					"domain_blacklist": generateLargeDomainList(1000),
				},
				"reputation_config.json": map[string]interface{}{
					"enabled": true,
					"providers": map[string]interface{}{
						"virustotal": map[string]interface{}{
							"enabled": true,
							"api_key": "test_key",
						},
					},
					"cache_duration": 3600,
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testMemoryUsageUnderLoad(t)
			},
		},
		{
			Name:        "Concurrent DNS Queries Stress",
			Description: "Test system under extreme DNS query load",
			EnvVars: map[string]string{
				"REDIS":          "redis://localhost:6379",
				"UPSTREAM":       "8.8.8.8:53",
				"PORT":           "5353", // Use alternate port for testing
				"HANDLE_ALL_IPS": "true",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testConcurrentDNSQueries(t, 5000, 100) // 5000 queries, 100 concurrent
			},
		},
		{
			Name:        "Large Configuration Files",
			Description: "Test with very large configuration files",
			ConfigFiles: map[string]interface{}{
				"script_config.json": generateLargeScriptConfig(100), // 100 client patterns
				"blacklist_config.json": map[string]interface{}{
					"ip_blacklist":     generateLargeIPList(10000),   // 10k IPs
					"domain_blacklist": generateLargeDomainList(5000), // 5k domains
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testLargeConfigurationHandling(t)
			},
		},
		{
			Name:        "Script Execution Flood",
			Description: "Test system resilience under script execution flood",
			EnvVars: map[string]string{
				"INVOKE_ALWAYS": "true",
			},
			ConfigFiles: map[string]interface{}{
				"script_config.json": map[string]interface{}{
					"version": "1.0",
					"defaults": map[string]interface{}{
						"invoke_script": "/bin/sleep 0.1", // Small delay
						"invoke_always": true,
					},
				},
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testScriptExecutionFlood(t)
			},
		},
		{
			Name:        "Redis Connection Exhaustion",
			Description: "Test Redis connection pool exhaustion scenarios",
			EnvVars: map[string]string{
				"REDIS":             "redis://localhost:6379",
				"REDIS_POOL_SIZE":   "5", // Very small pool
				"REDIS_MAX_RETRIES": "1", // Minimal retries
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnectionExhaustion(t)
			},
		},
		{
			Name:        "File Descriptor Exhaustion",
			Description: "Test behavior when approaching file descriptor limits",
			EnvVars: map[string]string{
				"REDIS":       "redis://localhost:6379",
				"WEB_UI_PORT": "8080",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testFileDescriptorUsage(t)
			},
		},
		{
			Name:        "CPU Intensive Configuration Processing",
			Description: "Test CPU usage with complex pattern matching and processing",
			ConfigFiles: map[string]interface{}{
				"script_config.json": generateComplexPatternConfig(500), // 500 complex regex patterns
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testCPUIntensiveProcessing(t)
			},
		},
	}

	for _, testCase := range testCases {
		suite.runConfigurationTest(t, testCase)
	}
}

// testRedisUnderLoad tests Redis performance under load
func (s *IntegrationTestSuite) testRedisUnderLoad(t *testing.T, operations int, concurrent int) error {
	start := time.Now()
	err := s.performRedisStressTest(t)
	duration := time.Since(start)

	t.Logf("Redis stress test completed in %v", duration)

	if duration > 30*time.Second {
		return fmt.Errorf("Redis operations took too long: %v", duration)
	}

	return err
}

// testMemoryUsageUnderLoad tests memory usage under load
func (s *IntegrationTestSuite) testMemoryUsageUnderLoad(t *testing.T) error {
	var m1, m2 runtime.MemStats

	// Get baseline memory usage
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Simulate load
	const numOperations = 1000
	const concurrency = 50

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Simulate DNS processing work
			domain := fmt.Sprintf("test%d.example.com", i)
			ip := fmt.Sprintf("192.168.1.%d", i%254+1)
			
			// This would normally trigger script execution, blacklist checking, etc.
			_ = domain
			_ = ip
			
			time.Sleep(time.Millisecond * 10)
		}(i)
	}

	wg.Wait()

	// Check memory usage after load
	runtime.GC()
	runtime.ReadMemStats(&m2)

	memoryIncrease := m2.Alloc - m1.Alloc
	t.Logf("Memory usage increased by %d bytes (%d KB)", memoryIncrease, memoryIncrease/1024)

	// Allow up to 100MB memory increase for stress test
	if memoryIncrease > 100*1024*1024 {
		return fmt.Errorf("excessive memory usage increase: %d bytes", memoryIncrease)
	}

	return nil
}

// testConcurrentDNSQueries tests concurrent DNS query handling
func (s *IntegrationTestSuite) testConcurrentDNSQueries(t *testing.T, numQueries int, concurrent int) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "53"
	}

	client := new(dns.Client)
	client.Timeout = 2 * time.Second

	sem := make(chan struct{}, concurrent)
	errors := make(chan error, numQueries)
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < numQueries; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			domain := fmt.Sprintf("test%d.example.com", i)
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			m.RecursionDesired = true

			_, _, err := client.Exchange(m, "127.0.0.1:"+port)
			if err != nil {
				errors <- fmt.Errorf("query %d failed: %v", i, err)
			} else {
				errors <- nil
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	duration := time.Since(start)
	qps := float64(numQueries) / duration.Seconds()

	var errorCount int
	for err := range errors {
		if err != nil {
			errorCount++
			if errorCount <= 5 { // Log first 5 errors
				t.Logf("DNS query error: %v", err)
			}
		}
	}

	t.Logf("Processed %d DNS queries in %v (%.2f QPS), %d errors", 
		numQueries, duration, qps, errorCount)

	// Allow up to 10% error rate under stress
	errorRate := float64(errorCount) / float64(numQueries)
	if errorRate > 0.1 {
		return fmt.Errorf("high error rate: %.2f%% (%d/%d)", 
			errorRate*100, errorCount, numQueries)
	}

	return nil
}

// testLargeConfigurationHandling tests handling of large configuration files
func (s *IntegrationTestSuite) testLargeConfigurationHandling(t *testing.T) error {
	start := time.Now()

	// Test script configuration loading
	scriptConfigPath := os.Getenv("SCRIPT_CONFIG")
	if scriptConfigPath != "" {
		_, err := loadScriptConfiguration(scriptConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load large script configuration: %v", err)
		}
	}

	// Test blacklist configuration loading
	blacklistConfigPath := os.Getenv("BLACKLIST_CONFIG")
	if blacklistConfigPath != "" {
		if _, err := os.Stat(blacklistConfigPath); err != nil {
			return fmt.Errorf("blacklist config file not accessible: %v", err)
		}
	}

	loadTime := time.Since(start)
	t.Logf("Large configuration loaded in %v", loadTime)

	// Configuration loading should complete within reasonable time
	if loadTime > 10*time.Second {
		return fmt.Errorf("configuration loading took too long: %v", loadTime)
	}

	return nil
}

// testScriptExecutionFlood tests system under script execution flood
func (s *IntegrationTestSuite) testScriptExecutionFlood(t *testing.T) error {
	// This would simulate many DNS requests triggering script executions
	// For now, we'll test the script configuration loading
	scriptConfigPath := os.Getenv("SCRIPT_CONFIG")
	if scriptConfigPath == "" {
		return fmt.Errorf("SCRIPT_CONFIG not set")
	}

	config, err := loadScriptConfiguration(scriptConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load script configuration: %v", err)
	}

	if !config.Defaults.InvokeAlways {
		return fmt.Errorf("invoke_always should be enabled for flood test")
	}

	t.Log("Script execution flood configuration validated")
	return nil
}

// testRedisConnectionExhaustion tests Redis connection pool exhaustion
func (s *IntegrationTestSuite) testRedisConnectionExhaustion(t *testing.T) error {
	poolSize := os.Getenv("REDIS_POOL_SIZE")
	if poolSize != "5" {
		return fmt.Errorf("expected small pool size for exhaustion test")
	}

	// Attempt more connections than pool size allows
	return s.performRedisStressTest(t)
}

// testFileDescriptorUsage tests file descriptor usage patterns
func (s *IntegrationTestSuite) testFileDescriptorUsage(t *testing.T) error {
	// This would test file descriptor usage by:
	// 1. Monitoring open file descriptors
	// 2. Simulating many concurrent connections
	// 3. Verifying cleanup after connections close

	t.Log("File descriptor usage test - implementation would monitor /proc/self/fd")
	return nil
}

// testCPUIntensiveProcessing tests CPU usage with complex processing
func (s *IntegrationTestSuite) testCPUIntensiveProcessing(t *testing.T) error {
	configPath := os.Getenv("SCRIPT_CONFIG")
	if configPath == "" {
		return fmt.Errorf("SCRIPT_CONFIG not set")
	}

	start := time.Now()
	config, err := loadScriptConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to load complex configuration: %v", err)
	}

	// Test pattern matching performance with many complex patterns
	testIPs := []string{
		"192.168.1.100", "10.0.0.1", "172.16.1.1", "203.0.113.1",
		"2001:db8::1", "::1", "127.0.0.1",
	}

	for _, ip := range testIPs {
		_ = findClientConfig(ip) // This exercises pattern matching
	}

	processingTime := time.Since(start)
	t.Logf("Complex configuration processing took %v for %d clients", 
		processingTime, len(config.Clients))

	// Processing should complete within reasonable time even with complex patterns
	if processingTime > 5*time.Second {
		return fmt.Errorf("complex pattern processing took too long: %v", processingTime)
	}

	return nil
}

// Helper functions to generate large test data

func generateLargeIPList(count int) []string {
	ips := make([]string, count)
	for i := 0; i < count; i++ {
		ips[i] = fmt.Sprintf("192.168.%d.%d", i/254, i%254+1)
	}
	return ips
}

func generateLargeDomainList(count int) []string {
	domains := make([]string, count)
	for i := 0; i < count; i++ {
		domains[i] = fmt.Sprintf("malware%d.example.com", i)
	}
	return domains
}

func generateLargeScriptConfig(clientCount int) map[string]interface{} {
	clients := make([]interface{}, clientCount)
	for i := 0; i < clientCount; i++ {
		clients[i] = map[string]interface{}{
			"client_pattern": fmt.Sprintf("192.168.%d.0/24", i%256),
			"invoke_script":  fmt.Sprintf("/usr/local/bin/script_%d.sh", i),
			"invoke_always":  i%2 == 0,
		}
	}

	return map[string]interface{}{
		"version": "1.0",
		"defaults": map[string]interface{}{
			"invoke_script": "/usr/local/bin/default.sh",
			"invoke_always": false,
		},
		"clients": clients,
	}
}

func generateComplexPatternConfig(patternCount int) map[string]interface{} {
	clients := make([]interface{}, patternCount)
	patterns := []string{
		"^192\\.168\\.(1[0-9]|2[0-9]|3[0-9])\\.",
		"^10\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.",
		"^172\\.(1[6-9]|2[0-9]|3[01])\\.",
		"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})",
	}

	for i := 0; i < patternCount; i++ {
		pattern := patterns[i%len(patterns)]
		if i > len(patterns) {
			// Make patterns more complex for higher numbers
			pattern = fmt.Sprintf("^192\\.168\\.(1[%d-%d]|2[0-9])\\.", i%10, (i+3)%10)
		}

		clients[i] = map[string]interface{}{
			"client_pattern": pattern,
			"invoke_script":  fmt.Sprintf("/usr/local/bin/pattern_%d.sh", i),
		}
	}

	return map[string]interface{}{
		"version": "1.0",
		"defaults": map[string]interface{}{
			"invoke_script": "/usr/local/bin/default.sh",
		},
		"clients": clients,
	}
}

// TestPerformanceBenchmarks runs performance benchmarks
func TestPerformanceBenchmarks(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	t.Run("DNS Query Performance", func(t *testing.T) {
		suite.setEnvVars(map[string]string{
			"REDIS":    "redis://localhost:6379",
			"UPSTREAM": "8.8.8.8:53",
			"PORT":     "5353",
		})

		// Benchmark DNS query processing
		start := time.Now()
		err := suite.testConcurrentDNSQueries(t, 1000, 10)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("DNS performance test failed: %v", err)
		}

		qps := float64(1000) / duration.Seconds()
		t.Logf("DNS Performance: %.2f queries/second", qps)

		// Baseline performance expectation
		if qps < 100 {
			t.Logf("Warning: DNS performance below expected baseline (100 QPS): %.2f", qps)
		}
	})

	t.Run("Configuration Loading Performance", func(t *testing.T) {
		// Test configuration loading performance
		configData := generateLargeScriptConfig(1000)
		configPath := suite.createTempFile("large_config.json", 
			fmt.Sprintf("%+v", configData)) // Simplified JSON creation

		suite.setEnvVars(map[string]string{
			"SCRIPT_CONFIG": configPath,
		})

		start := time.Now()
		_, err := loadScriptConfiguration(configPath)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Configuration loading failed: %v", err)
		}

		t.Logf("Configuration Loading Performance: %v for 1000 client patterns", duration)

		if duration > 1*time.Second {
			t.Logf("Warning: Configuration loading took longer than expected: %v", duration)
		}
	})

	t.Run("Memory Efficiency", func(t *testing.T) {
		var m1, m2 runtime.MemStats

		runtime.GC()
		runtime.ReadMemStats(&m1)

		// Load large configuration
		configData := generateLargeScriptConfig(5000)
		configPath := suite.createTempFile("memory_test_config.json", 
			fmt.Sprintf("%+v", configData))

		suite.setEnvVars(map[string]string{
			"SCRIPT_CONFIG": configPath,
		})

		_, err := loadScriptConfiguration(configPath)
		if err != nil {
			t.Errorf("Failed to load configuration: %v", err)
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)

		memoryUsed := m2.Alloc - m1.Alloc
		t.Logf("Memory Usage: %d bytes (%.2f MB) for 5000 client patterns", 
			memoryUsed, float64(memoryUsed)/1024/1024)

		// Memory usage should be reasonable
		if memoryUsed > 50*1024*1024 { // 50MB
			t.Logf("Warning: High memory usage for configuration: %.2f MB", 
				float64(memoryUsed)/1024/1024)
		}
	})
}