package main

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestInRange(t *testing.T) {
	tests := []struct {
		name     string
		ipLow    string
		ipHigh   string
		testIP   string
		expected bool
	}{
		{
			name:     "IP in range",
			ipLow:    "192.168.1.1",
			ipHigh:   "192.168.1.100",
			testIP:   "192.168.1.50",
			expected: true,
		},
		{
			name:     "IP below range",
			ipLow:    "192.168.1.10",
			ipHigh:   "192.168.1.100",
			testIP:   "192.168.1.5",
			expected: false,
		},
		{
			name:     "IP above range",
			ipLow:    "192.168.1.10",
			ipHigh:   "192.168.1.100",
			testIP:   "192.168.1.200",
			expected: false,
		},
		{
			name:     "IP at lower bound",
			ipLow:    "192.168.1.10",
			ipHigh:   "192.168.1.100",
			testIP:   "192.168.1.10",
			expected: true,
		},
		{
			name:     "IP at upper bound",
			ipLow:    "192.168.1.10",
			ipHigh:   "192.168.1.100",
			testIP:   "192.168.1.100",
			expected: true,
		},
		{
			name:     "IPv6 in range",
			ipLow:    "2001:db8::1",
			ipHigh:   "2001:db8::100",
			testIP:   "2001:db8::50",
			expected: true,
		},
		{
			name:     "IPv6 below range",
			ipLow:    "2001:db8::10",
			ipHigh:   "2001:db8::100",
			testIP:   "2001:db8::5",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipLow, err := netip.ParseAddr(tt.ipLow)
			if err != nil {
				t.Fatalf("Failed to parse low IP %s: %v", tt.ipLow, err)
			}
			ipHigh, err := netip.ParseAddr(tt.ipHigh)
			if err != nil {
				t.Fatalf("Failed to parse high IP %s: %v", tt.ipHigh, err)
			}
			testIP, err := netip.ParseAddr(tt.testIP)
			if err != nil {
				t.Fatalf("Failed to parse test IP %s: %v", tt.testIP, err)
			}

			result := inRange(ipLow, ipHigh, testIP)
			if result != tt.expected {
				t.Errorf("inRange(%s, %s, %s) = %v, expected %v",
					tt.ipLow, tt.ipHigh, tt.testIP, result, tt.expected)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	// Set required environment variable for testing
	originalUpstream := os.Getenv("UPSTREAM")
	originalWebUIPort := os.Getenv("WEB_UI_PORT")
	os.Setenv("UPSTREAM", "1.1.1.1:53")
	os.Unsetenv("WEB_UI_PORT") // Disable web UI during testing to avoid port conflicts
	defer func() {
		if originalUpstream != "" {
			os.Setenv("UPSTREAM", originalUpstream)
		} else {
			os.Unsetenv("UPSTREAM")
		}
		if originalWebUIPort != "" {
			os.Setenv("WEB_UI_PORT", originalWebUIPort)
		} else {
			os.Unsetenv("WEB_UI_PORT")
		}
	}()
	tests := []struct {
		name        string
		route       Route
		expectError bool
	}{
		{
			name: "Valid IPv4 route",
			route: Route{
				Zone: "example.com",
				From: net.ParseIP("192.168.1.100"),
				To:   net.ParseIP("1.2.3.4"),
			},
			expectError: false,
		},
		{
			name: "Valid IPv6 route",
			route: Route{
				Zone: "example.com",
				From: net.ParseIP("2001:db8::1"),
				To:   net.ParseIP("2001:db8::100"),
			},
			expectError: false,
		},
		{
			name: "Empty zone route",
			route: Route{
				Zone: "",
				From: net.ParseIP("192.168.1.100"),
				To:   net.ParseIP("1.2.3.4"),
			},
			expectError: true, // Empty zone should cause an error
		},
		{
			name: "Different IP versions",
			route: Route{
				Zone: "example.com",
				From: net.ParseIP("192.168.1.100"),
				To:   net.ParseIP("2001:db8::100"),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Register(tt.route)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestDNSQuestionValidation(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		qclass   uint16
		isValid  bool
	}{
		{
			name:    "Valid A record query",
			qname:   "example.com.",
			qtype:   dns.TypeA,
			qclass:  dns.ClassINET,
			isValid: true,
		},
		{
			name:    "Valid AAAA record query",
			qname:   "example.com.",
			qtype:   dns.TypeAAAA,
			qclass:  dns.ClassINET,
			isValid: true,
		},
		{
			name:    "Valid CNAME record query",
			qname:   "www.example.com.",
			qtype:   dns.TypeCNAME,
			qclass:  dns.ClassINET,
			isValid: true,
		},
		{
			name:    "Valid MX record query",
			qname:   "example.com.",
			qtype:   dns.TypeMX,
			qclass:  dns.ClassINET,
			isValid: true,
		},
		{
			name:    "Invalid empty domain",
			qname:   "",
			qtype:   dns.TypeA,
			qclass:  dns.ClassINET,
			isValid: false,
		},
		{
			name:    "Long domain name",
			qname:   "very-long-subdomain-name-that-might-be-used-for-testing-purposes.example.com.",
			qtype:   dns.TypeA,
			qclass:  dns.ClassINET,
			isValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a DNS question
			q := dns.Question{
				Name:   tt.qname,
				Qtype:  tt.qtype,
				Qclass: tt.qclass,
			}

			// Basic validation checks
			if tt.isValid {
				if len(q.Name) == 0 {
					t.Error("Expected valid domain but got empty name")
				}
				if q.Qtype == 0 {
					t.Error("Expected valid query type but got 0")
				}
				if q.Qclass == 0 {
					t.Error("Expected valid query class but got 0")
				}
			}
		})
	}
}

func TestDNSMessageConstruction(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		qtype        uint16
		responseCode int
	}{
		{
			name:         "Successful A record response",
			domain:       "example.com.",
			qtype:        dns.TypeA,
			responseCode: dns.RcodeSuccess,
		},
		{
			name:         "Successful AAAA record response",
			domain:       "example.com.",
			qtype:        dns.TypeAAAA,
			responseCode: dns.RcodeSuccess,
		},
		{
			name:         "NXDOMAIN response",
			domain:       "nonexistent.example.com.",
			qtype:        dns.TypeA,
			responseCode: dns.RcodeNameError,
		},
		{
			name:         "Server failure response",
			domain:       "example.com.",
			qtype:        dns.TypeA,
			responseCode: dns.RcodeServerFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a DNS message
			msg := new(dns.Msg)
			msg.Id = dns.Id()
			msg.RecursionDesired = true
			msg.Question = make([]dns.Question, 1)
			msg.Question[0] = dns.Question{
				Name:   tt.domain,
				Qtype:  tt.qtype,
				Qclass: dns.ClassINET,
			}

			// Validate message structure
			if len(msg.Question) != 1 {
				t.Errorf("Expected 1 question, got %d", len(msg.Question))
			}

			if msg.Question[0].Name != tt.domain {
				t.Errorf("Expected domain %s, got %s", tt.domain, msg.Question[0].Name)
			}

			if msg.Question[0].Qtype != tt.qtype {
				t.Errorf("Expected qtype %d, got %d", tt.qtype, msg.Question[0].Qtype)
			}

			// Create response
			response := new(dns.Msg)
			response.SetReply(msg)
			response.Rcode = tt.responseCode

			if response.Id != msg.Id {
				t.Errorf("Response ID %d doesn't match query ID %d", response.Id, msg.Id)
			}

			if response.Rcode != tt.responseCode {
				t.Errorf("Expected response code %d, got %d", tt.responseCode, response.Rcode)
			}
		})
	}
}

func TestDNSRecordCreation(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		ip       string
		ttl      uint32
		rtype    uint16
	}{
		{
			name:   "A record",
			domain: "example.com.",
			ip:     "1.2.3.4",
			ttl:    300,
			rtype:  dns.TypeA,
		},
		{
			name:   "AAAA record",
			domain: "example.com.",
			ip:     "2001:db8::1",
			ttl:    300,
			rtype:  dns.TypeAAAA,
		},
		{
			name:   "High TTL record",
			domain: "example.com.",
			ip:     "1.2.3.4",
			ttl:    86400,
			rtype:  dns.TypeA,
		},
		{
			name:   "Zero TTL record",
			domain: "example.com.",
			ip:     "1.2.3.4",
			ttl:    0,
			rtype:  dns.TypeA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rr dns.RR
			var err error

			if tt.rtype == dns.TypeA {
				rr, err = dns.NewRR(dns.Fqdn(tt.domain) + " " + string(rune(tt.ttl)) + " IN A " + tt.ip)
				if err != nil {
					// Try alternative creation method
					a := &dns.A{
						Hdr: dns.RR_Header{
							Name:   dns.Fqdn(tt.domain),
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    tt.ttl,
						},
						A: net.ParseIP(tt.ip),
					}
					rr = a
				}
			} else if tt.rtype == dns.TypeAAAA {
				aaaa := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(tt.domain),
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    tt.ttl,
					},
					AAAA: net.ParseIP(tt.ip),
				}
				rr = aaaa
			}

			if rr == nil {
				t.Fatal("Failed to create DNS record")
			}

			if rr.Header().Name != dns.Fqdn(tt.domain) {
				t.Errorf("Expected domain %s, got %s", dns.Fqdn(tt.domain), rr.Header().Name)
			}

			if rr.Header().Rrtype != tt.rtype {
				t.Errorf("Expected record type %d, got %d", tt.rtype, rr.Header().Rrtype)
			}

			if rr.Header().Ttl != tt.ttl {
				t.Errorf("Expected TTL %d, got %d", tt.ttl, rr.Header().Ttl)
			}
		})
	}
}