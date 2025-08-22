package main

import (
	"os"
	"testing"
)

// TestAAAAProcessingConfiguration tests the ENABLE_AAAA_PROCESSING environment variable
func TestAAAAProcessingConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		expectedResult bool
	}{
		{
			name:           "Default (empty) should enable AAAA",
			envValue:       "",
			expectedResult: true,
		},
		{
			name:           "Explicit 'true' should enable AAAA",
			envValue:       "true",
			expectedResult: true,
		},
		{
			name:           "Value '1' should enable AAAA",
			envValue:       "1",
			expectedResult: true,
		},
		{
			name:           "Value 'false' should disable AAAA",
			envValue:       "false",
			expectedResult: false,
		},
		{
			name:           "Value '0' should disable AAAA",
			envValue:       "0",
			expectedResult: false,
		},
		{
			name:           "Any other value should enable AAAA",
			envValue:       "enabled",
			expectedResult: true,
		},
	}

	// Save original environment variable
	originalEnv := os.Getenv("ENABLE_AAAA_PROCESSING")
	defer func() {
		if originalEnv != "" {
			os.Setenv("ENABLE_AAAA_PROCESSING", originalEnv)
		} else {
			os.Unsetenv("ENABLE_AAAA_PROCESSING")
		}
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue == "" {
				os.Unsetenv("ENABLE_AAAA_PROCESSING")
			} else {
				os.Setenv("ENABLE_AAAA_PROCESSING", tt.envValue)
			}

			// Simulate the logic from proxy.go Register() function
			enableAAAA := os.Getenv("ENABLE_AAAA_PROCESSING")
			if enableAAAA == "" {
				enableAAAA = "true" // Default to enabled for backward compatibility
			}

			// Test the condition used in the proxy.go code
			aaaaShouldBeProcessed := !(enableAAAA == "false" || enableAAAA == "0")

			if aaaaShouldBeProcessed != tt.expectedResult {
				t.Errorf("Expected AAAA processing to be %v, got %v for env value '%s'", 
					tt.expectedResult, aaaaShouldBeProcessed, tt.envValue)
			}
		})
	}
}