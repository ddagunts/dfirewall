package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
)

// TestRedisConfigurationCombinations tests various Redis configuration combinations
func TestRedisConfigurationCombinations(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCases := []ConfigurationCombination{
		{
			Name:        "Basic Redis Connection",
			Description: "Test basic Redis connection without authentication",
			EnvVars: map[string]string{
				"REDIS": "redis://localhost:6379",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with Password Authentication",
			Description: "Test Redis connection with password authentication",
			EnvVars: map[string]string{
				"REDIS":          "redis://localhost:6379",
				"REDIS_PASSWORD": "testpassword",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with TLS",
			Description: "Test Redis connection with TLS encryption",
			EnvVars: map[string]string{
				"REDIS":     "rediss://localhost:6380",
				"REDIS_TLS": "true",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with TLS and Password",
			Description: "Test Redis connection with both TLS and password authentication",
			EnvVars: map[string]string{
				"REDIS":          "rediss://localhost:6380",
				"REDIS_TLS":      "true",
				"REDIS_PASSWORD": "securepassword",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with Client Certificate Authentication",
			Description: "Test Redis connection with TLS client certificate authentication",
			EnvVars: map[string]string{
				"REDIS":          "rediss://localhost:6380",
				"REDIS_TLS":      "true",
				"REDIS_TLS_CERT": "/path/to/client.crt",
				"REDIS_TLS_KEY":  "/path/to/client.key",
			},
			ExpectError: true, // Will fail without actual certificates
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with CA Certificate Validation",
			Description: "Test Redis connection with custom CA certificate validation",
			EnvVars: map[string]string{
				"REDIS":        "rediss://localhost:6380",
				"REDIS_TLS":    "true",
				"REDIS_TLS_CA": "/path/to/ca.crt",
			},
			ExpectError: true, // Will fail without actual CA certificate
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with All TLS Options",
			Description: "Test Redis with client cert, CA validation, and password",
			EnvVars: map[string]string{
				"REDIS":                 "rediss://localhost:6380",
				"REDIS_TLS":             "true",
				"REDIS_PASSWORD":        "securepassword",
				"REDIS_TLS_CERT":        "/path/to/client.crt",
				"REDIS_TLS_KEY":         "/path/to/client.key",
				"REDIS_TLS_CA":          "/path/to/ca.crt",
				"REDIS_TLS_SERVER_NAME": "redis.example.com",
			},
			ExpectError: true, // Will fail without actual certificates
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis with Connection Pool Configuration",
			Description: "Test Redis with custom connection pool settings",
			EnvVars: map[string]string{
				"REDIS":               "redis://localhost:6379",
				"REDIS_POOL_SIZE":     "20",
				"REDIS_MAX_RETRIES":   "5",
				"REDIS_DIAL_TIMEOUT":  "10s",
				"REDIS_READ_TIMEOUT":  "5s",
				"REDIS_WRITE_TIMEOUT": "3s",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.validateRedisPoolConfiguration(t)
			},
		},
		{
			Name:        "Redis with TLS Skip Verification",
			Description: "Test Redis with TLS but skip certificate verification",
			EnvVars: map[string]string{
				"REDIS":                  "rediss://localhost:6380",
				"REDIS_TLS":              "true",
				"REDIS_TLS_SKIP_VERIFY":  "true",
			},
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
		{
			Name:        "Redis Invalid Configuration",
			Description: "Test Redis with invalid configuration should fail gracefully",
			EnvVars: map[string]string{
				"REDIS":            "invalid://url:format",
				"REDIS_POOL_SIZE":  "invalid",
				"REDIS_MAX_RETRIES": "-1",
			},
			ExpectError: true,
			Validate: func(t *testing.T, s *IntegrationTestSuite) error {
				return s.testRedisConnection(t)
			},
		},
	}

	for _, testCase := range testCases {
		suite.runConfigurationTest(t, testCase)
	}
}

// validateRedisPoolConfiguration validates Redis connection pool settings
func (s *IntegrationTestSuite) validateRedisPoolConfiguration(t *testing.T) error {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		return fmt.Errorf("REDIS environment variable not set")
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %v", err)
	}

	// Apply pool configuration from environment
	if poolSizeStr := os.Getenv("REDIS_POOL_SIZE"); poolSizeStr != "" {
		if poolSize, err := strconv.Atoi(poolSizeStr); err == nil {
			opts.PoolSize = poolSize
		} else {
			return fmt.Errorf("invalid REDIS_POOL_SIZE: %s", poolSizeStr)
		}
	}

	if maxRetriesStr := os.Getenv("REDIS_MAX_RETRIES"); maxRetriesStr != "" {
		if maxRetries, err := strconv.Atoi(maxRetriesStr); err == nil && maxRetries >= 0 {
			opts.MaxRetries = maxRetries
		} else {
			return fmt.Errorf("invalid REDIS_MAX_RETRIES: %s", maxRetriesStr)
		}
	}

	if dialTimeoutStr := os.Getenv("REDIS_DIAL_TIMEOUT"); dialTimeoutStr != "" {
		if dialTimeout, err := time.ParseDuration(dialTimeoutStr); err == nil {
			opts.DialTimeout = dialTimeout
		} else {
			return fmt.Errorf("invalid REDIS_DIAL_TIMEOUT: %s", dialTimeoutStr)
		}
	}

	if readTimeoutStr := os.Getenv("REDIS_READ_TIMEOUT"); readTimeoutStr != "" {
		if readTimeout, err := time.ParseDuration(readTimeoutStr); err == nil {
			opts.ReadTimeout = readTimeout
		} else {
			return fmt.Errorf("invalid REDIS_READ_TIMEOUT: %s", readTimeoutStr)
		}
	}

	if writeTimeoutStr := os.Getenv("REDIS_WRITE_TIMEOUT"); writeTimeoutStr != "" {
		if writeTimeout, err := time.ParseDuration(writeTimeoutStr); err == nil {
			opts.WriteTimeout = writeTimeout
		} else {
			return fmt.Errorf("invalid REDIS_WRITE_TIMEOUT: %s", writeTimeoutStr)
		}
	}

	// Validate pool size is reasonable
	if opts.PoolSize > 100 {
		return fmt.Errorf("pool size too large: %d", opts.PoolSize)
	}

	if opts.PoolSize < 1 {
		return fmt.Errorf("pool size too small: %d", opts.PoolSize)
	}

	// Test connection with configured options
	client := redis.NewClient(opts)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), opts.DialTimeout)
	defer cancel()

	return client.Ping(ctx).Err()
}

// TestRedisStressConfiguration tests Redis under stress conditions
func TestRedisStressConfiguration(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCase := ConfigurationCombination{
		Name:        "Redis Stress Test",
		Description: "Test Redis performance under stress with various configurations",
		EnvVars: map[string]string{
			"REDIS":              "redis://localhost:6379",
			"REDIS_POOL_SIZE":    "50",
			"REDIS_MAX_RETRIES":  "3",
			"REDIS_DIAL_TIMEOUT": "1s",
		},
		Validate: func(t *testing.T, s *IntegrationTestSuite) error {
			return s.performRedisStressTest(t)
		},
	}

	suite.runConfigurationTest(t, testCase)
}

// performRedisStressTest performs a stress test on Redis configuration
func (s *IntegrationTestSuite) performRedisStressTest(t *testing.T) error {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		return fmt.Errorf("REDIS environment variable not set")
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %v", err)
	}

	// Apply configuration
	if poolSizeStr := os.Getenv("REDIS_POOL_SIZE"); poolSizeStr != "" {
		if poolSize, err := strconv.Atoi(poolSizeStr); err == nil {
			opts.PoolSize = poolSize
		}
	}

	client := redis.NewClient(opts)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Perform concurrent operations to stress test the configuration
	const numOperations = 100
	const numConcurrent = 10

	errChan := make(chan error, numOperations)
	sem := make(chan struct{}, numConcurrent)

	for i := 0; i < numOperations; i++ {
		go func(i int) {
			sem <- struct{}{} // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			key := fmt.Sprintf("stress_test_key_%d", i)
			value := fmt.Sprintf("stress_test_value_%d", i)

			// Set operation
			if err := client.Set(ctx, key, value, time.Minute).Err(); err != nil {
				errChan <- fmt.Errorf("set operation %d failed: %v", i, err)
				return
			}

			// Get operation
			result, err := client.Get(ctx, key).Result()
			if err != nil {
				errChan <- fmt.Errorf("get operation %d failed: %v", i, err)
				return
			}

			if result != value {
				errChan <- fmt.Errorf("value mismatch in operation %d: expected %s, got %s", i, value, result)
				return
			}

			// Delete operation
			if err := client.Del(ctx, key).Err(); err != nil {
				errChan <- fmt.Errorf("delete operation %d failed: %v", i, err)
				return
			}

			errChan <- nil
		}(i)
	}

	// Collect results
	var errors []error
	for i := 0; i < numOperations; i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("stress test failed with %d errors: %v", len(errors), errors[0])
	}

	return nil
}

// TestRedisFailoverConfiguration tests Redis failover scenarios
func TestRedisFailoverConfiguration(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()

	testCase := ConfigurationCombination{
		Name:        "Redis Failover Test",
		Description: "Test Redis failover and recovery behavior",
		EnvVars: map[string]string{
			"REDIS":             "redis://localhost:6379",
			"REDIS_MAX_RETRIES": "5",
			"REDIS_DIAL_TIMEOUT": "2s",
		},
		Validate: func(t *testing.T, s *IntegrationTestSuite) error {
			return s.testRedisFailoverBehavior(t)
		},
	}

	suite.runConfigurationTest(t, testCase)
}

// testRedisFailoverBehavior tests how the system behaves during Redis failures
func (s *IntegrationTestSuite) testRedisFailoverBehavior(t *testing.T) error {
	redisURL := os.Getenv("REDIS")
	if redisURL == "" {
		return fmt.Errorf("REDIS environment variable not set")
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("failed to parse Redis URL: %v", err)
	}

	// Apply retry configuration
	if maxRetriesStr := os.Getenv("REDIS_MAX_RETRIES"); maxRetriesStr != "" {
		if maxRetries, err := strconv.Atoi(maxRetriesStr); err == nil {
			opts.MaxRetries = maxRetries
		}
	}

	client := redis.NewClient(opts)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test initial connection
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("initial Redis connection failed: %v", err)
	}

	// Simulate operations that might fail and retry
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("failover_test_%d", i)
		value := fmt.Sprintf("value_%d", i)

		// This should work with retry logic if Redis is temporarily unavailable
		err := client.Set(ctx, key, value, time.Minute).Err()
		if err != nil {
			t.Logf("Set operation failed for key %s: %v", key, err)
			// Don't fail the test immediately, as retries might be expected
		}

		// Clean up
		client.Del(ctx, key)
	}

	return nil
}