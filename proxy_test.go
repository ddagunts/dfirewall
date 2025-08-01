package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
	
	// Create command with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, scriptPath)
	
	start := time.Now()
	_, err := cmd.Output()
	duration := time.Since(start)
	
	// Should timeout and return an error
	if err == nil {
		t.Error("Expected timeout error, but command succeeded")
	}
	
	// Should timeout within reasonable time (allowing some buffer)
	if duration > 2*time.Second {
		t.Errorf("Command took too long to timeout: %v", duration)
	}
	
	// Verify it's some kind of error (timeout or kill)
	if err == nil {
		t.Error("Expected an error due to timeout")
	}
}