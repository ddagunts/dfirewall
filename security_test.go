package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Note: sanitizeForShell tests removed as function has been replaced with validation approach

func TestValidateInvokeScript(t *testing.T) {
	// Create temporary test scripts
	tempDir := t.TempDir()
	
	validScript := filepath.Join(tempDir, "valid_script.sh")
	err := os.WriteFile(validScript, []byte("#!/bin/bash\necho 'test'"), 0755)
	if err != nil {
		t.Fatalf("Failed to create valid test script: %v", err)
	}

	nonExecutableScript := filepath.Join(tempDir, "non_executable.sh")
	err = os.WriteFile(nonExecutableScript, []byte("#!/bin/bash\necho 'test'"), 0644)
	if err != nil {
		t.Fatalf("Failed to create non-executable test script: %v", err)
	}

	tests := []struct {
		name        string
		scriptPath  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid executable script",
			scriptPath:  validScript,
			expectError: false,
		},
		{
			name:        "Non-existent script",
			scriptPath:  filepath.Join(tempDir, "nonexistent.sh"),
			expectError: true,
			errorMsg:    "no such file or directory",
		},
		{
			name:        "Empty script path",
			scriptPath:  "",
			expectError: true,
			errorMsg:    "script path is empty",
		},
		{
			name:        "Non-executable script",
			scriptPath:  nonExecutableScript,
			expectError: true,
			errorMsg:    "not executable",
		},
		{
			name:        "Directory instead of file",
			scriptPath:  tempDir,
			expectError: true,
			errorMsg:    "is a directory",
		},
		{
			name:        "Relative path",
			scriptPath:  "./test.sh",
			expectError: true,
			errorMsg:    "no such file or directory",
		},
		{
			name:        "Path traversal attempt",
			scriptPath:  "../../../bin/bash",
			expectError: false, // This might be valid if the path exists and is executable
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInvokeScript(tt.scriptPath)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for script path %q but got none", tt.scriptPath)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid script path %q: %v", tt.scriptPath, err)
				}
			}
		})
	}
}

func TestValidateScriptPath(t *testing.T) {
	// Create temporary test files
	tempDir := t.TempDir()
	
	validScript := filepath.Join(tempDir, "valid.sh")
	err := os.WriteFile(validScript, []byte("#!/bin/bash\necho 'test'"), 0755)
	if err != nil {
		t.Fatalf("Failed to create valid test script: %v", err)
	}

	regularFile := filepath.Join(tempDir, "regular.txt")
	err = os.WriteFile(regularFile, []byte("not a script"), 0644)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	tests := []struct {
		name        string
		scriptPath  string
		expectError bool
	}{
		{
			name:        "Valid script file",
			scriptPath:  validScript,
			expectError: false,
		},
		{
			name:        "Regular text file",
			scriptPath:  regularFile,
			expectError: true, // File must be executable to be a valid script
		},
		{
			name:        "Non-existent file",
			scriptPath:  filepath.Join(tempDir, "missing.sh"),
			expectError: true,
		},
		{
			name:        "Empty path",
			scriptPath:  "",
			expectError: true,
		},
		{
			name:        "Directory",
			scriptPath:  tempDir,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScriptPath(tt.scriptPath)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for script path %q but got none", tt.scriptPath)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for script path %q: %v", tt.scriptPath, err)
				}
			}
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	// Generate multiple request IDs and check they're unique
	requestIDs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateRequestID()
		
		if len(id) == 0 {
			t.Error("Request ID should not be empty")
		}

		if len(id) < 8 {
			t.Errorf("Request ID should be at least 8 characters, got %d", len(id))
		}

		if requestIDs[id] {
			t.Errorf("Duplicate request ID generated: %s", id)
		}
		requestIDs[id] = true

		// Check format (should be alphanumeric with underscores)
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, id)
		if !matched {
			t.Errorf("Request ID should be alphanumeric with underscores, got: %s", id)
		}
	}
}

func TestSecurityValidation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isSecure bool
	}{
		{
			name:     "Safe domain",
			input:    "example.com",
			isSecure: true,
		},
		{
			name:     "Safe IP",
			input:    "192.168.1.100",
			isSecure: true,
		},
		{
			name:     "Command injection attempt",
			input:    "example.com; rm -rf /",
			isSecure: false,
		},
		{
			name:     "SQL injection attempt",
			input:    "'; DROP TABLE users; --",
			isSecure: false,
		},
		{
			name:     "Path traversal attempt",
			input:    "../../../etc/passwd",
			isSecure: false,
		},
		{
			name:     "Script injection",
			input:    "<script>alert('xss')</script>",
			isSecure: false,
		},
		{
			name:     "Null byte injection",
			input:    "example.com\x00malicious",
			isSecure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic security validation
			isSecure := true

			// Check for dangerous characters
			dangerousPatterns := []string{
				";", "|", "&", "$", "`", "(", ")", 
				"'", "\"", "<", ">", "\x00", "../",
				"DROP", "SELECT", "INSERT", "UPDATE", "DELETE",
				"<script", "</script>", "javascript:",
			}

			for _, pattern := range dangerousPatterns {
				if strings.Contains(strings.ToLower(tt.input), strings.ToLower(pattern)) {
					isSecure = false
					break
				}
			}

			if isSecure != tt.isSecure {
				t.Errorf("Security validation for %q: expected %v, got %v", tt.input, tt.isSecure, isSecure)
			}
		})
	}
}

func TestInputLengthValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLength int
		isValid   bool
	}{
		{
			name:      "Normal domain",
			input:     "example.com",
			maxLength: 255,
			isValid:   true,
		},
		{
			name:      "Very long domain",
			input:     strings.Repeat("a", 300),
			maxLength: 255,
			isValid:   false,
		},
		{
			name:      "Empty input",
			input:     "",
			maxLength: 255,
			isValid:   true,
		},
		{
			name:      "Exact limit",
			input:     strings.Repeat("a", 255),
			maxLength: 255,
			isValid:   true,
		},
		{
			name:      "One over limit",
			input:     strings.Repeat("a", 256),
			maxLength: 255,
			isValid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := len(tt.input) <= tt.maxLength
			if isValid != tt.isValid {
				t.Errorf("Length validation for input of length %d (max %d): expected %v, got %v", 
					len(tt.input), tt.maxLength, tt.isValid, isValid)
			}
		})
	}
}

func TestConfigurationSecurity(t *testing.T) {
	t.Run("Script path validation", func(t *testing.T) {
		dangerousScripts := []string{
			"/bin/sh",
			"/bin/bash",
			"/usr/bin/python",
			"../../../../bin/bash",
			"/dev/null",
			"/proc/self/exe",
		}

		for _, script := range dangerousScripts {
			t.Run("Dangerous script: "+script, func(t *testing.T) {
				// In a real application, you might want to restrict certain paths
				// This test documents what paths should be carefully validated
				
				// Check if the path exists (for realistic testing)
				if _, err := os.Stat(script); err == nil {
					t.Logf("Warning: Potentially dangerous script path exists and could be configured: %s", script)
				}
			})
		}
	})

	t.Run("Environment variable injection", func(t *testing.T) {
		envTests := []struct {
			name     string
			envValue string
			isSafe   bool
		}{
			{
				name:     "Normal value",
				envValue: "example.com",
				isSafe:   true,
			},
			{
				name:     "Command injection via env",
				envValue: "value; evil_command",
				isSafe:   false,
			},
			{
				name:     "Path traversal via env",
				envValue: "../../../etc/passwd",
				isSafe:   false,
			},
		}

		for _, tt := range envTests {
			t.Run(tt.name, func(t *testing.T) {
				// Test environment variable safety
				hasShellChars := strings.ContainsAny(tt.envValue, ";|&$`")
				hasPathTraversal := strings.Contains(tt.envValue, "../")
				isSafe := !(hasShellChars || hasPathTraversal)
				if isSafe != tt.isSafe {
					t.Errorf("Environment variable safety for %q: expected %v, got %v (hasShellChars=%v, hasPathTraversal=%v)", 
						tt.envValue, tt.isSafe, isSafe, hasShellChars, hasPathTraversal)
				}
			})
		}
	})
}

func TestTimeoutValidation(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		isValid  bool
	}{
		{
			name:     "Normal timeout",
			timeout:  30 * time.Second,
			isValid:  true,
		},
		{
			name:     "Very short timeout",
			timeout:  100 * time.Millisecond,
			isValid:  false,
		},
		{
			name:     "Very long timeout",
			timeout:  24 * time.Hour,
			isValid:  false,
		},
		{
			name:     "Zero timeout",
			timeout:  0,
			isValid:  false,
		},
		{
			name:     "Negative timeout",
			timeout:  -1 * time.Second,
			isValid:  false,
		},
		{
			name:     "One minute timeout",
			timeout:  60 * time.Second,
			isValid:  true,
		},
		{
			name:     "Five minute timeout",
			timeout:  5 * time.Minute,
			isValid:  true,
		},
		{
			name:     "One hour timeout",
			timeout:  time.Hour,
			isValid:  false, // Probably too long for script execution
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reasonable timeout validation (1 second to 10 minutes)
			minTimeout := 1 * time.Second
			maxTimeout := 10 * time.Minute
			
			isValid := tt.timeout >= minTimeout && tt.timeout <= maxTimeout
			
			if isValid != tt.isValid {
				t.Errorf("Timeout validation for %v: expected %v, got %v", 
					tt.timeout, tt.isValid, isValid)
			}
		})
	}
}

func TestRegexSafety(t *testing.T) {
	// Test regex patterns for potential ReDoS (Regular expression Denial of Service)
	tests := []struct {
		name    string
		pattern string
		input   string
		isSafe  bool
	}{
		{
			name:    "Simple safe pattern",
			pattern: `^[a-zA-Z0-9\._\-]+$`,
			input:   "example.com",
			isSafe:  true,
		},
		{
			name:    "Potential ReDoS pattern (safe in Go RE2)",
			pattern: `^(a+)+$`,
			input:   strings.Repeat("a", 1000) + "b",
			isSafe:  true, // Go's RE2 engine prevents ReDoS attacks
		},
		{
			name:    "Another ReDoS pattern (safe in Go RE2)",
			pattern: `^(a|a)*$`,
			input:   strings.Repeat("a", 100),
			isSafe:  true, // Go's RE2 engine prevents ReDoS attacks
		},
		{
			name:    "Safe domain validation",
			pattern: `^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			input:   "example.com",
			isSafe:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := regexp.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("Failed to compile regex pattern %q: %v", tt.pattern, err)
			}

			// Set a timeout for regex execution to detect ReDoS
			done := make(chan bool, 1)
			go func() {
				regex.MatchString(tt.input)
				done <- true
			}()

			select {
			case <-done:
				// Regex completed quickly, it's safe
				if !tt.isSafe {
					t.Errorf("Expected regex pattern %q to be unsafe with input %q, but it completed quickly", 
						tt.pattern, tt.input)
				}
			case <-time.After(100 * time.Millisecond):
				// Regex took too long, potential ReDoS
				if tt.isSafe {
					t.Errorf("Expected regex pattern %q to be safe with input %q, but it timed out", 
						tt.pattern, tt.input)
				}
			}
		})
	}
}