package main

import (
	"testing"
)

func TestShouldSkipFirewallRule(t *testing.T) {
	tests := []struct {
		name     string
		ipAddr   string
		expected bool
	}{
		// IPv4 addresses that should be skipped
		{"IPv4 0.0.0.0", "0.0.0.0", true},
		{"IPv4 0.x.x.x range", "0.1.2.3", true},
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback range", "127.255.255.254", true},
		{"IPv4 multicast", "224.0.0.1", true},
		{"IPv4 multicast range", "239.255.255.255", true},
		{"IPv4 reserved", "240.0.0.1", true},
		{"IPv4 reserved range", "255.255.255.255", true},
		
		// IPv6 addresses that should be skipped
		{"IPv6 unspecified", "::", true},
		{"IPv6 unspecified alt", "::0", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 multicast", "ff00::1", true},
		{"IPv6 multicast range", "ff02::1", true},
		
		// Valid addresses that should NOT be skipped
		{"IPv4 private RFC1918", "192.168.1.1", false},
		{"IPv4 private RFC1918", "10.0.0.1", false},
		{"IPv4 private RFC1918", "172.16.0.1", false},
		{"IPv4 public", "8.8.8.8", false},
		{"IPv4 public", "1.1.1.1", false},
		{"IPv6 public", "2001:4860:4860::8888", false},
		{"IPv6 link-local", "fe80::1", false},
		{"IPv6 unique local", "fc00::1", false},
		
		// Invalid IP addresses that should be skipped
		{"Invalid IP format", "invalid-ip", true},
		{"Empty string", "", true},
		{"Invalid IPv4", "999.999.999.999", true},
		{"Invalid IPv6", "gggg::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipFirewallRule(tt.ipAddr)
			if result != tt.expected {
				t.Errorf("shouldSkipFirewallRule(%q) = %v, want %v", tt.ipAddr, result, tt.expected)
			}
		})
	}
}

func TestShouldSkipFirewallRuleEdgeCases(t *testing.T) {
	// Test specific edge cases around boundaries
	edgeCases := []struct {
		name     string
		ipAddr   string
		expected bool
		reason   string
	}{
		{"IPv4 1.0.0.0 (valid)", "1.0.0.0", false, "First valid IPv4 after 0.x.x.x range"},
		{"IPv4 126.255.255.255 (valid)", "126.255.255.255", false, "Last valid IPv4 before loopback"},
		{"IPv4 128.0.0.0 (valid)", "128.0.0.0", false, "First valid IPv4 after loopback"},
		{"IPv4 223.255.255.255 (valid)", "223.255.255.255", false, "Last valid IPv4 before multicast"},
		{"IPv6 fe80::1 (link-local valid)", "fe80::1", false, "Link-local should be allowed"},
		{"IPv6 fc00::1 (unique local valid)", "fc00::1", false, "Unique local should be allowed"},
	}

	for _, tt := range edgeCases {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipFirewallRule(tt.ipAddr)
			if result != tt.expected {
				t.Errorf("shouldSkipFirewallRule(%q) = %v, want %v (%s)", 
					tt.ipAddr, result, tt.expected, tt.reason)
			}
		})
	}
}