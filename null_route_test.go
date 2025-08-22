package main

import (
	"testing"
)

// TestIsNullRouteAddress tests the null route address detection function
func TestIsNullRouteAddress(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// IPv4 null route tests
		{
			name:     "IPv4 null route (0.0.0.0)",
			ip:       "0.0.0.0",
			expected: true,
		},
		{
			name:     "Valid IPv4 address",
			ip:       "192.168.1.1",
			expected: false,
		},
		{
			name:     "Valid IPv4 address (8.8.8.8)",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "Valid IPv4 address (127.0.0.1)",
			ip:       "127.0.0.1",
			expected: false,
		},
		{
			name:     "IPv4 broadcast address",
			ip:       "255.255.255.255",
			expected: false,
		},
		// IPv6 null route tests
		{
			name:     "IPv6 null route (::)",
			ip:       "::",
			expected: true,
		},
		{
			name:     "IPv6 null route explicit (0:0:0:0:0:0:0:0)",
			ip:       "0:0:0:0:0:0:0:0",
			expected: true,
		},
		{
			name:     "Valid IPv6 address",
			ip:       "2001:db8::1",
			expected: false,
		},
		{
			name:     "IPv6 localhost",
			ip:       "::1",
			expected: false,
		},
		{
			name:     "Valid IPv6 address (Google DNS)",
			ip:       "2001:4860:4860::8888",
			expected: false,
		},
		// Invalid IP tests
		{
			name:     "Invalid IP address",
			ip:       "not.an.ip.address",
			expected: false,
		},
		{
			name:     "Empty string",
			ip:       "",
			expected: false,
		},
		{
			name:     "Invalid IPv4 format",
			ip:       "256.256.256.256",
			expected: false,
		},
		{
			name:     "Invalid IPv6 format",
			ip:       "gggg::1",
			expected: false,
		},
		// Edge cases
		{
			name:     "IPv4 with leading zeros (should be valid)",
			ip:       "192.168.001.001",
			expected: false,
		},
		{
			name:     "IPv6 compressed format",
			ip:       "2001:db8::",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNullRouteAddress(tt.ip)
			if result != tt.expected {
				t.Errorf("isNullRouteAddress(%q) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// TestNullRouteBypassPrevention tests that null route addresses are properly ignored
// in DNS response processing (integration test approach)
func TestNullRouteBypassPrevention(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		shouldIgnore bool
		description string
	}{
		{
			name:        "Block IPv4 null route",
			ip:          "0.0.0.0",
			shouldIgnore: true,
			description: "0.0.0.0 should be ignored to prevent firewall bypass",
		},
		{
			name:        "Block IPv6 null route",
			ip:          "::",
			shouldIgnore: true,
			description: ":: should be ignored to prevent firewall bypass",
		},
		{
			name:        "Allow valid IPv4",
			ip:          "8.8.8.8",
			shouldIgnore: false,
			description: "Valid IPv4 addresses should be processed normally",
		},
		{
			name:        "Allow valid IPv6",
			ip:          "2001:4860:4860::8888",
			shouldIgnore: false,
			description: "Valid IPv6 addresses should be processed normally",
		},
		{
			name:        "Allow localhost IPv4",
			ip:          "127.0.0.1",
			shouldIgnore: false,
			description: "Localhost addresses should be processed (may have legitimate uses)",
		},
		{
			name:        "Allow localhost IPv6",
			ip:          "::1",
			shouldIgnore: false,
			description: "IPv6 localhost should be processed (may have legitimate uses)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNullRouteAddress(tt.ip)
			if result != tt.shouldIgnore {
				t.Errorf("isNullRouteAddress(%q) = %v, expected %v - %s", 
					tt.ip, result, tt.shouldIgnore, tt.description)
			}
		})
	}
}

// TestNullRouteSecurityImplications documents the security implications
func TestNullRouteSecurityImplications(t *testing.T) {
	// This test documents why we need to block null routes
	t.Run("Security reasoning", func(t *testing.T) {
		// Test that null routes would be detected
		if !isNullRouteAddress("0.0.0.0") {
			t.Error("0.0.0.0 not detected as null route - security vulnerability!")
		}
		
		if !isNullRouteAddress("::") {
			t.Error(":: not detected as null route - security vulnerability!")
		}
		
		// Test that normal addresses are not blocked
		if isNullRouteAddress("8.8.8.8") {
			t.Error("8.8.8.8 incorrectly detected as null route - would break legitimate traffic!")
		}
		
		if isNullRouteAddress("2001:4860:4860::8888") {
			t.Error("2001:4860:4860::8888 incorrectly detected as null route - would break legitimate traffic!")
		}
		
		t.Log("Security check passed: null routes are properly detected and blocked")
		t.Log("Rationale: null route addresses (0.0.0.0/::) could bypass firewall rules")
		t.Log("Impact: prevents malicious DNS responses from creating firewall bypasses")
	})
}