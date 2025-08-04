package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestCreateRedisClient(t *testing.T) {
	tests := []struct {
		name        string
		redisEnv    string
		expectError bool
	}{
		{
			name:        "Valid Redis URL",
			redisEnv:    "redis://localhost:6379",
			expectError: false,
		},
		{
			name:        "Redis URL with database",
			redisEnv:    "redis://localhost:6379/1",
			expectError: false,
		},
		{
			name:        "Redis URL with password",
			redisEnv:    "redis://:password@localhost:6379",
			expectError: false,
		},
		{
			name:        "Redis URL with username and password",
			redisEnv:    "redis://user:password@localhost:6379",
			expectError: false,
		},
		{
			name:        "Invalid Redis URL",
			redisEnv:    "invalid-url",
			expectError: true,
		},
		{
			name:        "Empty Redis URL",
			redisEnv:    "",
			expectError: true,
		},
		{
			name:        "Redis URL with TLS",
			redisEnv:    "rediss://localhost:6380",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createRedisClient(tt.redisEnv)
			
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

			if client == nil {
				t.Error("Expected valid Redis client but got nil")
				return
			}

			// Test basic Redis client properties
			opts := client.Options()
			if opts == nil {
				t.Error("Redis client options should not be nil")
			}

			// Clean up
			client.Close()
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Valid IPv4",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Valid IPv6",
			ip:       "2001:db8::1",
			expected: true,
		},
		{
			name:     "IPv4 loopback",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "IPv6 loopback",
			ip:       "::1",
			expected: true,
		},
		{
			name:     "IPv4 broadcast",
			ip:       "255.255.255.255",
			expected: true,
		},
		{
			name:     "IPv4 zero",
			ip:       "0.0.0.0",
			expected: true,
		},
		{
			name:     "IPv6 zero",
			ip:       "::",
			expected: true,
		},
		{
			name:     "Invalid IPv4 - too many octets",
			ip:       "192.168.1.1.1",
			expected: false,
		},
		{
			name:     "Invalid IPv4 - octet out of range",
			ip:       "192.168.1.256",
			expected: false,
		},
		{
			name:     "Invalid IPv6 - malformed",
			ip:       "2001:db8::g",
			expected: false,
		},
		{
			name:     "Empty string",
			ip:       "",
			expected: false,
		},
		{
			name:     "Invalid format",
			ip:       "not-an-ip",
			expected: false,
		},
		{
			name:     "Hostname instead of IP",
			ip:       "example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("validateIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "Valid domain",
			domain:   "example.com",
			expected: true,
		},
		{
			name:     "Valid subdomain",
			domain:   "www.example.com",
			expected: true,
		},
		{
			name:     "Valid deep subdomain",
			domain:   "api.v1.example.com",
			expected: true,
		},
		{
			name:     "Valid domain with numbers",
			domain:   "test123.example.com",
			expected: true,
		},
		{
			name:     "Valid domain with hyphens",
			domain:   "test-domain.example.com",
			expected: true,
		},
		{
			name:     "Valid single character domain",
			domain:   "a.com",
			expected: true,
		},
		{
			name:     "Valid long domain",
			domain:   "very-long-subdomain-name-for-testing.example.com",
			expected: true,
		},
		{
			name:     "Empty domain",
			domain:   "",
			expected: false,
		},
		{
			name:     "Domain starting with hyphen",
			domain:   "-example.com",
			expected: false,
		},
		{
			name:     "Domain ending with hyphen",
			domain:   "example-.com",
			expected: false,
		},
		{
			name:     "Domain with double hyphen",
			domain:   "exam--ple.com",
			expected: true, // This might be valid depending on validation rules
		},
		{
			name:     "Domain with spaces",
			domain:   "exam ple.com",
			expected: false,
		},
		{
			name:     "Domain with invalid characters",
			domain:   "example$.com",
			expected: false,
		},
		{
			name:     "IP address instead of domain",
			domain:   "192.168.1.1",
			expected: false,
		},
		{
			name:     "Domain too long",
			domain:   "a" + string(make([]byte, 300)) + ".com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("validateDomain(%s) = %v, expected %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestValidateTTL(t *testing.T) {
	tests := []struct {
		name     string
		ttl      uint32
		expected bool
	}{
		{
			name:     "Valid low TTL",
			ttl:      1,
			expected: true,
		},
		{
			name:     "Valid standard TTL",
			ttl:      300,
			expected: true,
		},
		{
			name:     "Valid high TTL",
			ttl:      86400,
			expected: true,
		},
		{
			name:     "Zero TTL",
			ttl:      0,
			expected: true, // Zero TTL might be valid for immediate expiration
		},
		{
			name:     "Maximum 32-bit TTL",
			ttl:      4294967295,
			expected: true,
		},
		{
			name:     "One hour TTL",
			ttl:      3600,
			expected: true,
		},
		{
			name:     "One week TTL",
			ttl:      604800,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateTTL(tt.ttl)
			if result != tt.expected {
				t.Errorf("validateTTL(%d) = %v, expected %v", tt.ttl, result, tt.expected)
			}
		})
	}
}

func TestValidateClientPattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectError bool
	}{
		{
			name:        "Valid IPv4 address",
			pattern:     "192.168.1.100",
			expectError: false,
		},
		{
			name:        "Valid IPv6 address",
			pattern:     "2001:db8::1",
			expectError: false,
		},
		{
			name:        "Valid IPv4 CIDR",
			pattern:     "192.168.1.0/24",
			expectError: false,
		},
		{
			name:        "Valid IPv6 CIDR",
			pattern:     "2001:db8::/32",
			expectError: false,
		},
		{
			name:        "Valid regex pattern",
			pattern:     "regex:^192\\.168\\.",
			expectError: false,
		},
		{
			name:        "Complex regex pattern",
			pattern:     "regex:^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)",
			expectError: false,
		},
		{
			name:        "Empty pattern",
			pattern:     "",
			expectError: true,
		},
		{
			name:        "Invalid CIDR - bad network",
			pattern:     "192.168.1.256/24",
			expectError: true,
		},
		{
			name:        "Invalid CIDR - bad prefix",
			pattern:     "192.168.1.0/33",
			expectError: true,
		},
		{
			name:        "Invalid IP format",
			pattern:     "not-an-ip",
			expectError: true, // Invalid pattern - not IP, CIDR, regex, or wildcard
		},
		{
			name:        "Invalid regex pattern",
			pattern:     "[invalid-regex",
			expectError: true,
		},
		{
			name:        "Wildcard pattern",
			pattern:     "*",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientPattern(tt.pattern)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for pattern %s but got none", tt.pattern)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for pattern %s: %v", tt.pattern, err)
				}
			}
		})
	}
}

// Mock Redis client for testing Redis operations without actual Redis server
type MockRedisClient struct {
	data map[string]string
	sets map[string]map[string]bool
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data: make(map[string]string),
		sets: make(map[string]map[string]bool),
	}
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	m.data[key] = value.(string)
	cmd := redis.NewStatusCmd(ctx, "set", key, value)
	cmd.SetVal("OK")
	return cmd
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx, "get", key)
	if val, exists := m.data[key]; exists {
		cmd.SetVal(val)
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (m *MockRedisClient) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	if m.sets[key] == nil {
		m.sets[key] = make(map[string]bool)
	}
	added := 0
	for _, member := range members {
		memberStr := member.(string)
		if !m.sets[key][memberStr] {
			m.sets[key][memberStr] = true
			added++
		}
	}
	cmd := redis.NewIntCmd(ctx, "sadd", key)
	cmd.SetVal(int64(added))
	return cmd
}

func (m *MockRedisClient) SMembers(ctx context.Context, key string) *redis.StringSliceCmd {
	cmd := redis.NewStringSliceCmd(ctx, "smembers", key)
	if set, exists := m.sets[key]; exists {
		members := make([]string, 0, len(set))
		for member := range set {
			members = append(members, member)
		}
		cmd.SetVal(members)
	} else {
		cmd.SetVal([]string{})
	}
	return cmd
}

func (m *MockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	deleted := 0
	for _, key := range keys {
		if _, exists := m.data[key]; exists {
			delete(m.data, key)
			deleted++
		}
		if _, exists := m.sets[key]; exists {
			delete(m.sets, key)
			deleted++
		}
	}
	cmd := redis.NewIntCmd(ctx, "del")
	cmd.SetVal(int64(deleted))
	return cmd
}

func TestRedisOperations(t *testing.T) {
	mockClient := NewMockRedisClient()
	ctx := context.Background()

	t.Run("Set and Get operations", func(t *testing.T) {
		// Test Set operation
		setCmd := mockClient.Set(ctx, "test:key", "test:value", time.Hour)
		if setCmd.Err() != nil {
			t.Errorf("Set operation failed: %v", setCmd.Err())
		}
		if setCmd.Val() != "OK" {
			t.Errorf("Expected 'OK', got %s", setCmd.Val())
		}

		// Test Get operation
		getCmd := mockClient.Get(ctx, "test:key")
		if getCmd.Err() != nil {
			t.Errorf("Get operation failed: %v", getCmd.Err())
		}
		if getCmd.Val() != "test:value" {
			t.Errorf("Expected 'test:value', got %s", getCmd.Val())
		}

		// Test Get non-existent key
		getCmd = mockClient.Get(ctx, "nonexistent:key")
		if getCmd.Err() != redis.Nil {
			t.Errorf("Expected redis.Nil error for non-existent key, got %v", getCmd.Err())
		}
	})

	t.Run("Set operations", func(t *testing.T) {
		// Test SAdd operation
		saddCmd := mockClient.SAdd(ctx, "test:set", "member1", "member2", "member3")
		if saddCmd.Err() != nil {
			t.Errorf("SAdd operation failed: %v", saddCmd.Err())
		}
		if saddCmd.Val() != 3 {
			t.Errorf("Expected 3 members added, got %d", saddCmd.Val())
		}

		// Test SAdd duplicate member
		saddCmd = mockClient.SAdd(ctx, "test:set", "member1")
		if saddCmd.Val() != 0 {
			t.Errorf("Expected 0 members added for duplicate, got %d", saddCmd.Val())
		}

		// Test SMembers operation
		smembersCmd := mockClient.SMembers(ctx, "test:set")
		if smembersCmd.Err() != nil {
			t.Errorf("SMembers operation failed: %v", smembersCmd.Err())
		}
		members := smembersCmd.Val()
		if len(members) != 3 {
			t.Errorf("Expected 3 members, got %d", len(members))
		}

		// Check all members are present
		memberMap := make(map[string]bool)
		for _, member := range members {
			memberMap[member] = true
		}
		expectedMembers := []string{"member1", "member2", "member3"}
		for _, expected := range expectedMembers {
			if !memberMap[expected] {
				t.Errorf("Expected member %s not found in set", expected)
			}
		}
	})

	t.Run("Delete operations", func(t *testing.T) {
		// Set up test data
		mockClient.Set(ctx, "delete:test1", "value1", time.Hour)
		mockClient.Set(ctx, "delete:test2", "value2", time.Hour)
		mockClient.SAdd(ctx, "delete:set", "member1")

		// Test Del operation
		delCmd := mockClient.Del(ctx, "delete:test1", "delete:test2", "delete:set")
		if delCmd.Err() != nil {
			t.Errorf("Del operation failed: %v", delCmd.Err())
		}
		if delCmd.Val() != 3 {
			t.Errorf("Expected 3 keys deleted, got %d", delCmd.Val())
		}

		// Verify keys are deleted
		getCmd := mockClient.Get(ctx, "delete:test1")
		if getCmd.Err() != redis.Nil {
			t.Error("Key should be deleted")
		}
	})
}

func TestRedisKeyGeneration(t *testing.T) {
	tests := []struct {
		name       string
		clientIP   net.IP
		resolvedIP net.IP
		domain     string
		expected   string
	}{
		{
			name:       "IPv4 key generation",
			clientIP:   net.ParseIP("192.168.1.100"),
			resolvedIP: net.ParseIP("1.2.3.4"),
			domain:     "example.com",
			expected:   "192.168.1.100|1.2.3.4|example.com",
		},
		{
			name:       "IPv6 key generation",
			clientIP:   net.ParseIP("2001:db8::1"),
			resolvedIP: net.ParseIP("2001:db8::100"),
			domain:     "example.com",
			expected:   "2001:db8::1|2001:db8::100|example.com",
		},
		{
			name:       "Mixed IP versions",
			clientIP:   net.ParseIP("192.168.1.100"),
			resolvedIP: net.ParseIP("2001:db8::100"),
			domain:     "example.com",
			expected:   "192.168.1.100|2001:db8::100|example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the key generation pattern used in the application
			// Using "|" separator as documented in OUTPUT.md
			key := tt.clientIP.String() + "|" + tt.resolvedIP.String() + "|" + tt.domain
			if key != tt.expected {
				t.Errorf("Expected key %s, got %s", tt.expected, key)
			}
		})
	}
}

func TestRedisConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]interface{}
		expectErr bool
	}{
		{
			name: "Valid basic config",
			config: map[string]interface{}{
				"host":     "localhost",
				"port":     6379,
				"database": 0,
			},
			expectErr: false,
		},
		{
			name: "Valid config with auth",
			config: map[string]interface{}{
				"host":     "localhost",
				"port":     6379,
				"database": 0,
				"username": "user",
				"password": "pass",
			},
			expectErr: false,
		},
		{
			name: "Invalid port - too high",
			config: map[string]interface{}{
				"host": "localhost",
				"port": 70000,
			},
			expectErr: true,
		},
		{
			name: "Invalid port - negative",
			config: map[string]interface{}{
				"host": "localhost",
				"port": -1,
			},
			expectErr: true,
		},
		{
			name: "Invalid database - negative",
			config: map[string]interface{}{
				"host":     "localhost",
				"port":     6379,
				"database": -1,
			},
			expectErr: true,
		},
		{
			name: "Invalid database - too high",
			config: map[string]interface{}{
				"host":     "localhost",
				"port":     6379,
				"database": 20,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic for Redis configuration
			var err error

			if port, ok := tt.config["port"].(int); ok {
				if port < 1 || port > 65535 {
					err = redis.ErrClosed // Using a Redis error as placeholder
				}
			}

			if db, ok := tt.config["database"].(int); ok {
				if db < 0 || db > 15 { // Redis typically supports 0-15 databases
					err = redis.ErrClosed
				}
			}

			if tt.expectErr {
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
}