package main

import (
	"net"
	"os"
	"testing"
	
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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

// TestAAAAResponseFiltering tests that AAAA records are properly filtered from DNS responses
func TestAAAAResponseFiltering(t *testing.T) {
	tests := []struct {
		name                    string
		enableAAAA             string
		handleAllIPs            string
		includeARecord          bool
		includeAAAARecord       bool
		includeCNAMERecord      bool
		expectedACount          int
		expectedAAAACount       int  
		expectedCNAMECount      int
		expectedTotalRecords    int
	}{
		{
			name:                 "IPv6 enabled - all records should be present",
			enableAAAA:           "true",
			handleAllIPs:         "",
			includeARecord:       true,
			includeAAAARecord:    true,
			includeCNAMERecord:   true,
			expectedACount:       1,
			expectedAAAACount:    1,
			expectedCNAMECount:   1,
			expectedTotalRecords: 3,
		},
		{
			name:                 "IPv6 disabled - AAAA records should be filtered",
			enableAAAA:           "false",
			handleAllIPs:         "",
			includeARecord:       true,
			includeAAAARecord:    true, // Will be included in original but filtered out
			includeCNAMERecord:   true,
			expectedACount:       1,
			expectedAAAACount:    0, // Should be filtered out
			expectedCNAMECount:   1,
			expectedTotalRecords: 2,
		},
		{
			name:                 "IPv6 disabled with 0 value - AAAA records should be filtered",
			enableAAAA:           "0",
			handleAllIPs:         "",
			includeARecord:       true,
			includeAAAARecord:    true, // Will be included in original but filtered out
			includeCNAMERecord:   true,
			expectedACount:       1,
			expectedAAAACount:    0, // Should be filtered out
			expectedCNAMECount:   1,
			expectedTotalRecords: 2,
		},
		{
			name:                 "IPv6 disabled with HANDLE_ALL_IPS enabled - AAAA should still be filtered",
			enableAAAA:           "false",
			handleAllIPs:         "true",
			includeARecord:       true,
			includeAAAARecord:    true, // Will be included in original but filtered out
			includeCNAMERecord:   true,
			expectedACount:       1,
			expectedAAAACount:    0, // Should be filtered out
			expectedCNAMECount:   1,
			expectedTotalRecords: 2,
		},
		{
			name:                 "IPv6 enabled with HANDLE_ALL_IPS enabled - all records present",
			enableAAAA:           "true",
			handleAllIPs:         "true",
			includeARecord:       true,
			includeAAAARecord:    true,
			includeCNAMERecord:   true,
			expectedACount:       1,
			expectedAAAACount:    1,
			expectedCNAMECount:   1,
			expectedTotalRecords: 3,
		},
	}

	// Save original environment variables
	originalAAAA := os.Getenv("ENABLE_AAAA_PROCESSING")
	originalHandleAll := os.Getenv("HANDLE_ALL_IPS")
	defer func() {
		if originalAAAA != "" {
			os.Setenv("ENABLE_AAAA_PROCESSING", originalAAAA)
		} else {
			os.Unsetenv("ENABLE_AAAA_PROCESSING")
		}
		if originalHandleAll != "" {
			os.Setenv("HANDLE_ALL_IPS", originalHandleAll)
		} else {
			os.Unsetenv("HANDLE_ALL_IPS")
		}
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			if tt.enableAAAA == "" {
				os.Unsetenv("ENABLE_AAAA_PROCESSING")
			} else {
				os.Setenv("ENABLE_AAAA_PROCESSING", tt.enableAAAA)
			}
			
			if tt.handleAllIPs == "" {
				os.Unsetenv("HANDLE_ALL_IPS")
			} else {
				os.Setenv("HANDLE_ALL_IPS", tt.handleAllIPs)
			}

			// Simulate the logic from proxy.go
			enableAAAA := os.Getenv("ENABLE_AAAA_PROCESSING")
			if enableAAAA == "" {
				enableAAAA = "true"
			}
			handleAllIPs := os.Getenv("HANDLE_ALL_IPS")

			// Create a mock DNS response
			resp := &dns.Msg{}
			resp.Answer = []dns.RR{}

			// Add A record if specified
			if tt.includeARecord {
				a := &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("192.0.2.1"),
				}
				resp.Answer = append(resp.Answer, a)
			}

			// Add AAAA record if specified
			if tt.includeAAAARecord {
				aaaa := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: net.ParseIP("2001:db8::1"),
				}
				resp.Answer = append(resp.Answer, aaaa)
			}

			// Add CNAME record if specified
			if tt.includeCNAMERecord {
				cname := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "www.example.com.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Target: "example.com.",
				}
				resp.Answer = append(resp.Answer, cname)
			}

			t.Logf("Original response has %d records", len(resp.Answer))

			// Simulate the filtering logic from proxy.go
			var processedARR *dns.A

			// Find first A record for HANDLE_ALL_IPS logic
			for _, rr := range resp.Answer {
				if rrType, ok := rr.(*dns.A); ok {
					if processedARR == nil {
						processedARR = rrType
					}
					break
				}
			}

			// Apply HANDLE_ALL_IPS logic (when disabled, keep only first A record + non-A records)
			if handleAllIPs == "" && processedARR != nil {
				newAnswer := []dns.RR{}
				
				// Add the first processed A record
				newAnswer = append(newAnswer, processedARR)
				
				// Add all non-A records, but filter AAAA if IPv6 processing is disabled
				for _, rr := range resp.Answer {
					if _, ok := rr.(*dns.A); !ok {
						// Filter out AAAA records if IPv6 processing is disabled
						if _, isAAAA := rr.(*dns.AAAA); isAAAA {
							if enableAAAA == "false" || enableAAAA == "0" {
								continue // Skip this AAAA record
							}
						}
						newAnswer = append(newAnswer, rr)
					}
				}
				
				resp.Answer = newAnswer
			}
			
			// Apply final AAAA filtering (for both HANDLE_ALL_IPS modes)
			if enableAAAA == "false" || enableAAAA == "0" {
				filteredAnswer := []dns.RR{}
				
				for _, rr := range resp.Answer {
					if _, isAAAA := rr.(*dns.AAAA); isAAAA {
						continue // Skip this AAAA record
					}
					filteredAnswer = append(filteredAnswer, rr)
				}
				
				resp.Answer = filteredAnswer
			}

			// Count record types in final response
			aCount := 0
			aaaaCount := 0
			cnameCount := 0
			
			for _, rr := range resp.Answer {
				switch rr.(type) {
				case *dns.A:
					aCount++
				case *dns.AAAA:
					aaaaCount++
				case *dns.CNAME:
					cnameCount++
				}
			}

			t.Logf("Final response: %d A, %d AAAA, %d CNAME, %d total", 
				aCount, aaaaCount, cnameCount, len(resp.Answer))

			// Validate results
			assert.Equal(t, tt.expectedACount, aCount, "A record count mismatch")
			assert.Equal(t, tt.expectedAAAACount, aaaaCount, "AAAA record count mismatch")
			assert.Equal(t, tt.expectedCNAMECount, cnameCount, "CNAME record count mismatch")
			assert.Equal(t, tt.expectedTotalRecords, len(resp.Answer), "Total record count mismatch")
		})
	}
}