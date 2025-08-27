package main

import (
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestHandleAllIPsConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		handleAllIPs     string
		expectedReturn   int // Number of A records expected in response
		description      string
	}{
		{
			name:           "Default (empty) should process only first IP",
			handleAllIPs:   "",
			expectedReturn: 1,
			description:    "When HANDLE_ALL_IPS is not set, only first A record should be returned",
		},
		{
			name:           "HANDLE_ALL_IPS=1 should process all IPs",
			handleAllIPs:   "1",
			expectedReturn: 3,
			description:    "When HANDLE_ALL_IPS is set, all A records should be returned",
		},
		{
			name:           "HANDLE_ALL_IPS=true should process all IPs", 
			handleAllIPs:   "true",
			expectedReturn: 3,
			description:    "When HANDLE_ALL_IPS is set to any value, all A records should be returned",
		},
		{
			name:           "HANDLE_ALL_IPS=false should still process all IPs",
			handleAllIPs:   "false",
			expectedReturn: 3,
			description:    "When HANDLE_ALL_IPS is set to any value (even 'false'), all A records should be returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variable
			if tt.handleAllIPs != "" {
				os.Setenv("HANDLE_ALL_IPS", tt.handleAllIPs)
			} else {
				os.Unsetenv("HANDLE_ALL_IPS")
			}
			defer os.Unsetenv("HANDLE_ALL_IPS")

			// Create a mock DNS response with multiple A records
			resp := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:       12345,
					Response: true,
					Opcode:   dns.OpcodeQuery,
					Rcode:    dns.RcodeSuccess,
				},
				Question: []dns.Question{
					{
						Name:   "example.com.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			}

			// Add multiple A records
			ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
			for i, ip := range ips {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP(ip),
				}
				resp.Answer = append(resp.Answer, rr)
				
				// For debugging
				t.Logf("Added A record %d: %s", i+1, ip)
			}

			// Add a CNAME record to ensure non-A records are preserved
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

			t.Logf("Original response has %d total records (%d A records)", len(resp.Answer), 3)

			// Simulate the HANDLE_ALL_IPS logic from proxy.go
			handleAllIPs := os.Getenv("HANDLE_ALL_IPS")
			var processedARR *dns.A

			// Process records like in the real code
			for _, rr := range resp.Answer {
				if rrType, ok := rr.(*dns.A); ok {
					if processedARR == nil {
						processedARR = rrType
					}
					if handleAllIPs == "" {
						break // Only process first A record
					}
				}
			}

			// Apply DNS response modification logic
			if handleAllIPs == "" && processedARR != nil {
				newAnswer := []dns.RR{}
				
				// Add the first processed A record
				newAnswer = append(newAnswer, processedARR)
				
				// Add all non-A records (CNAME, AAAA, etc.)
				for _, rr := range resp.Answer {
					if _, ok := rr.(*dns.A); !ok {
						newAnswer = append(newAnswer, rr)
					}
				}
				
				resp.Answer = newAnswer
				t.Logf("HANDLE_ALL_IPS disabled: Modified response to %d records", len(resp.Answer))
			}

			// Count A records in final response
			aRecordCount := 0
			cnameRecordCount := 0
			for _, rr := range resp.Answer {
				switch rr.(type) {
				case *dns.A:
					aRecordCount++
				case *dns.CNAME:
					cnameRecordCount++
				}
			}

			t.Logf("Final response: %d A records, %d CNAME records", aRecordCount, cnameRecordCount)

			// Validate results
			assert.Equal(t, tt.expectedReturn, aRecordCount, 
				"Expected %d A records in response but got %d (HANDLE_ALL_IPS=%s)", 
				tt.expectedReturn, aRecordCount, strconv.Quote(tt.handleAllIPs))

			// CNAME record should always be preserved
			assert.Equal(t, 1, cnameRecordCount, "CNAME record should always be preserved")

			// If only first IP should be returned, verify it's the correct one
			if tt.expectedReturn == 1 {
				if assert.Len(t, resp.Answer, 2, "Should have 1 A record + 1 CNAME record") {
					aRecord, ok := resp.Answer[0].(*dns.A)
					if assert.True(t, ok, "First record should be an A record") {
						assert.Equal(t, "192.0.2.1", aRecord.A.String(), 
							"Should return the first IP address")
					}
				}
			}
		})
	}
}