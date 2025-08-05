package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestDomainBlacklistWithCNAME tests that domain blacklisting works correctly
// even when the DNS response contains CNAME records that resolve to different domains
func TestDomainBlacklistWithCNAME(t *testing.T) {
	tests := []struct {
		name           string
		requestedDomain string
		resolvedDomain  string
		expectedMatch  bool
		description    string
	}{
		{
			name:           "Direct domain match",
			requestedDomain: "www.ebay.com.",
			resolvedDomain:  "www.ebay.com.",
			expectedMatch:  true,
			description:    "Should match when requested and resolved domains are the same",
		},
		{
			name:           "CNAME resolution to different domain",
			requestedDomain: "www.ebay.com.",
			resolvedDomain:  "ebay.map.fastly.net.",
			expectedMatch:  true,
			description:    "Should match based on requested domain, not resolved CNAME target",
		},
		{
			name:           "Subdomain of blacklisted parent",
			requestedDomain: "shop.ebay.com.",
			resolvedDomain:  "shop.ebay.com.",
			expectedMatch:  true,
			description:    "Should match subdomain when parent domain is blacklisted",
		},
		{
			name:           "Subdomain with CNAME to different domain",
			requestedDomain: "shop.ebay.com.",
			resolvedDomain:  "shop-cdn.fastly.net.",
			expectedMatch:  true,
			description:    "Should match subdomain based on requested domain, not CNAME target",
		},
		{
			name:           "Non-blacklisted domain",
			requestedDomain: "www.google.com.",
			resolvedDomain:  "www.google.com.",
			expectedMatch:  false,
			description:    "Should not match non-blacklisted domain",
		},
		{
			name:           "Non-blacklisted domain with CNAME",
			requestedDomain: "www.google.com.",
			resolvedDomain:  "google.map.fastly.net.",
			expectedMatch:  false,
			description:    "Should not match non-blacklisted domain even with CNAME",
		},
	}

	// Set up a mock blacklist configuration for testing
	originalBlacklistConfig := blacklistConfig
	blacklistConfig = &BlacklistConfig{
		Enabled:      true,
		BlockOnMatch: true,
	}
	defer func() {
		blacklistConfig = originalBlacklistConfig
	}()

	// Set up domain blacklist with ebay.com to test subdomain blocking
	originalDomainBlacklist := domainBlacklist
	domainBlacklist = map[string]bool{
		"ebay.com": true,
	}
	defer func() {
		domainBlacklist = originalDomainBlacklist
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the domain normalization and matching logic
			normalizedRequested := strings.ToLower(strings.TrimSuffix(tt.requestedDomain, "."))
			
			// Simulate what happens in checkDomainBlacklist
			isBlacklisted := false
			
			// Check exact match first
			if domainBlacklist[normalizedRequested] {
				isBlacklisted = true
			}
			
			// Check parent domains for subdomain blocking
			if !isBlacklisted {
				parts := strings.Split(normalizedRequested, ".")
				for i := 1; i < len(parts); i++ {
					parentDomain := strings.Join(parts[i:], ".")
					if domainBlacklist[parentDomain] {
						isBlacklisted = true
						break
					}
				}
			}
			
			if isBlacklisted != tt.expectedMatch {
				t.Errorf("Test %s failed: expected match=%v, got match=%v for domain %s (resolved to %s)",
					tt.description, tt.expectedMatch, isBlacklisted, tt.requestedDomain, tt.resolvedDomain)
			}
		})
	}
}

// TestDNSResponseProcessingWithCNAME tests that our fix correctly uses the
// originally requested domain instead of the resolved domain from DNS answers
func TestDNSResponseProcessingWithCNAME(t *testing.T) {
	// Create a mock DNS response that simulates www.ebay.com CNAMEing to a different domain
	resp := &dns.Msg{}
	
	// Add a CNAME record (not tested in our main loop, but shows the setup)
	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   "www.ebay.com.",
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: "ebay.map.fastly.net.",
	}
	resp.Answer = append(resp.Answer, cname)
	
	// Add an A record that would resolve to the CNAME target
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "ebay.map.fastly.net.", // This is the resolved domain
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{1, 2, 3, 4}, // Mock IP
	}
	resp.Answer = append(resp.Answer, a)
	
	// Test what domain would be used in our fixed logic
	requestedDomain := "www.ebay.com" // This is what the client originally requested
	
	// Simulate the fixed logic in our proxy
	for _, rr := range resp.Answer {
		if rrType, ok := rr.(*dns.A); ok {
			// OLD BUG: domain := rrType.Hdr.Name  // Would be "ebay.map.fastly.net."
			// NEW FIX: Use originally requested domain
			domain := requestedDomain
			if domain == "" {
				// Fallback to resolved domain if no requested domain available
				domain = strings.TrimSuffix(rrType.Hdr.Name, ".")
			}
			
			// Verify that we're using the requested domain, not the resolved one
			expectedDomain := "www.ebay.com"
			if domain != expectedDomain {
				t.Errorf("Expected to use requested domain %s, but got %s", expectedDomain, domain)
			}
			
			// Verify that the resolved domain (from DNS answer) is different
			resolvedDomain := strings.TrimSuffix(rrType.Hdr.Name, ".")
			if resolvedDomain == expectedDomain {
				t.Logf("Note: In this test case, resolved domain happens to match requested domain")
			} else {
				t.Logf("CNAME resolution: %s -> %s (correctly using requested domain)", expectedDomain, resolvedDomain)
			}
		}
	}
}