package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
)

// TestSimpleRedisConnectivity tests basic Redis connectivity for integration testing
func TestSimpleRedisConnectivity(t *testing.T) {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		redisURL = "redis://127.0.0.1:6380"
	}

	t.Logf("Testing Redis connectivity to: %s", redisURL)

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("Failed to parse Redis URL: %v", err)
	}

	client := redis.NewClient(opts)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test basic connectivity
	err = client.Ping(ctx).Err()
	if err != nil {
		t.Fatalf("Redis connection failed: %v", err)
	}

	t.Log("✓ Redis connectivity test passed")

	// Test basic operations
	testKey := "integration_test_key"
	testValue := "integration_test_value"

	err = client.Set(ctx, testKey, testValue, time.Minute).Err()
	if err != nil {
		t.Fatalf("Redis SET failed: %v", err)
	}

	result, err := client.Get(ctx, testKey).Result()
	if err != nil {
		t.Fatalf("Redis GET failed: %v", err)
	}

	if result != testValue {
		t.Fatalf("Expected %s, got %s", testValue, result)
	}

	t.Log("✓ Redis operations test passed")

	// Cleanup
	client.Del(ctx, testKey)
}

// TestIntegrationTestFramework tests the integration test framework itself
func TestIntegrationTestFramework(t *testing.T) {
	t.Log("Testing integration test framework...")

	// Test environment variable access
	testMode := os.Getenv("DFIREWALL_TEST_MODE")
	if testMode != "1" {
		t.Error("DFIREWALL_TEST_MODE should be set to 1")
	}

	debug := os.Getenv("DEBUG")
	if debug != "1" {
		t.Error("DEBUG should be set to 1")
	}

	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		t.Error("UPSTREAM should be set")
	}

	t.Logf("✓ Environment variables: TEST_MODE=%s, DEBUG=%s, UPSTREAM=%s", testMode, debug, upstream)

	// Test file system access
	tempDir := "/tmp/test_integration"
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	testFile := tempDir + "/test_file.txt"
	testContent := "integration test content"

	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(content) != testContent {
		t.Fatalf("File content mismatch: expected %s, got %s", testContent, string(content))
	}

	// Cleanup
	os.RemoveAll(tempDir)

	t.Log("✓ File system operations test passed")
}

// TestConfigurationCombinationFramework tests the configuration combination framework
func TestConfigurationCombinationFramework(t *testing.T) {
	t.Log("Testing configuration combination framework...")

	// Simulate a configuration combination test
	testCombination := struct {
		Name        string
		Description string
		EnvVars     map[string]string
		ExpectError bool
	}{
		Name:        "Test Configuration",
		Description: "Test configuration combination framework",
		EnvVars: map[string]string{
			"TEST_VAR1": "value1",
			"TEST_VAR2": "value2",
		},
		ExpectError: false,
	}

	t.Logf("Running test combination: %s", testCombination.Name)

	// Set test environment variables
	for key, value := range testCombination.EnvVars {
		originalValue := os.Getenv(key)
		os.Setenv(key, value)
		
		// Verify it was set
		if os.Getenv(key) != value {
			t.Errorf("Failed to set environment variable %s", key)
		}
		
		// Restore original value
		if originalValue != "" {
			os.Setenv(key, originalValue)
		} else {
			os.Unsetenv(key)
		}
	}

	t.Log("✓ Configuration combination framework test passed")
}

// TestRedisStressSimple performs a simple stress test on Redis
func TestRedisStressSimple(t *testing.T) {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		redisURL = "redis://127.0.0.1:6380"
	}

	t.Logf("Running simple Redis stress test...")

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("Failed to parse Redis URL: %v", err)
	}

	client := redis.NewClient(opts)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform multiple operations
	const numOperations = 100
	start := time.Now()

	for i := 0; i < numOperations; i++ {
		key := fmt.Sprintf("stress_test_%d", i)
		value := fmt.Sprintf("value_%d", i)

		err := client.Set(ctx, key, value, time.Minute).Err()
		if err != nil {
			t.Errorf("SET operation %d failed: %v", i, err)
			continue
		}

		result, err := client.Get(ctx, key).Result()
		if err != nil {
			t.Errorf("GET operation %d failed: %v", i, err)
			continue
		}

		if result != value {
			t.Errorf("Value mismatch for operation %d: expected %s, got %s", i, value, result)
		}

		// Cleanup
		client.Del(ctx, key)
	}

	duration := time.Since(start)
	opsPerSecond := float64(numOperations*3) / duration.Seconds() // SET + GET + DEL

	t.Logf("✓ Completed %d operations in %v (%.2f ops/sec)", numOperations*3, duration, opsPerSecond)

	if opsPerSecond < 100 {
		t.Logf("Warning: Performance below expected baseline (100 ops/sec): %.2f", opsPerSecond)
	}
}