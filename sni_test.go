package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// Test SNI configuration loading and validation
func TestLoadSNIInspectionConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		expectError bool
		errorText   string
	}{
		{
			name: "valid configuration",
			configJSON: `{
				"enabled": true,
				"proxy_ips": ["192.168.1.100"],
				"proxy_ports": [8443],
				"client_configs": [
					{
						"client_pattern": "192.168.1.0/24",
						"enabled": true
					}
				],
				"domain_configs": [
					{
						"domain_pattern": "*.example.com",
						"enabled": true
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "empty proxy IPs",
			configJSON: `{
				"enabled": true,
				"proxy_ips": [],
				"proxy_ports": [8443]
			}`,
			expectError: true,
			errorText:   "proxy_ips cannot be empty",
		},
		{
			name: "empty proxy ports",
			configJSON: `{
				"enabled": true,
				"proxy_ips": ["192.168.1.100"],
				"proxy_ports": []
			}`,
			expectError: true,
			errorText:   "proxy_ports cannot be empty",
		},
		{
			name: "invalid IP address",
			configJSON: `{
				"enabled": true,
				"proxy_ips": ["invalid-ip"],
				"proxy_ports": [8443]
			}`,
			expectError: true,
			errorText:   "invalid proxy IP",
		},
		{
			name: "invalid port",
			configJSON: `{
				"enabled": true,
				"proxy_ips": ["192.168.1.100"],
				"proxy_ports": [70000]
			}`,
			expectError: true,
			errorText:   "invalid proxy port",
		},
		{
			name: "invalid client pattern",
			configJSON: `{
				"enabled": true,
				"proxy_ips": ["192.168.1.100"],
				"proxy_ports": [8443],
				"client_configs": [
					{
						"client_pattern": "",
						"enabled": true
					}
				]
			}`,
			expectError: true,
			errorText:   "client_pattern cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tempDir := t.TempDir()
			configFile := tempDir + "/sni_config.json"
			err := os.WriteFile(configFile, []byte(tt.configJSON), 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			config, err := loadSNIInspectionConfiguration(configFile)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", tt.errorText)
					return
				}
				if !strings.Contains(err.Error(), tt.errorText) {
					t.Errorf("Expected error containing '%s', got: %s", tt.errorText, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Error("Expected config to be non-nil")
				return
			}

			// Verify defaults are set
			if config.ConnectionTimeout == 0 {
				t.Error("Expected default ConnectionTimeout to be set")
			}
			if config.HandshakeTimeout == 0 {
				t.Error("Expected default HandshakeTimeout to be set")
			}
		})
	}
}

// Test SNI inspection decision logic
func TestShouldUseSNIInspection(t *testing.T) {
	// Setup test configuration
	originalConfig := sniInspectionConfig
	defer func() { sniInspectionConfig = originalConfig }()

	sniInspectionConfig = &SNIInspectionConfig{
		Enabled:   true,
		ProxyIPs:  []string{"10.0.0.1", "10.0.0.2"},
		ClientConfigs: []SNIClientConfig{
			{
				ClientPattern: "192.168.1.0/24",
				Enabled:       true,
				ProxyIP:       "10.0.0.1",
			},
			{
				ClientPattern: "10.0.0.0/8", 
				Enabled:       false,
			},
		},
		DomainConfigs: []SNIDomainConfig{
			{
				DomainPattern: "*.example.com",
				Enabled:       true,
				ProxyIP:       "10.0.0.2",
			},
		},
	}

	tests := []struct {
		name           string
		clientIP       string
		domain         string
		expectEnabled  bool
		expectedProxyIP string
	}{
		{
			name:           "client match with custom proxy IP",
			clientIP:       "192.168.1.50",
			domain:         "test.com",
			expectEnabled:  true,
			expectedProxyIP: "10.0.0.1",
		},
		{
			name:           "client match but disabled",
			clientIP:       "10.0.0.50",
			domain:         "test.com",
			expectEnabled:  false,
			expectedProxyIP: "",
		},
		{
			name:           "domain match with custom proxy IP",
			clientIP:       "1.2.3.4",
			domain:         "test.example.com",
			expectEnabled:  true,
			expectedProxyIP: "10.0.0.2",
		},
		{
			name:           "no match",
			clientIP:       "1.2.3.4",
			domain:         "test.com",
			expectEnabled:  false,
			expectedProxyIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, proxyIP := shouldUseSNIInspection(tt.clientIP, tt.domain)

			if enabled != tt.expectEnabled {
				t.Errorf("Expected enabled=%v, got %v", tt.expectEnabled, enabled)
			}

			if proxyIP != tt.expectedProxyIP {
				t.Errorf("Expected proxyIP=%s, got %s", tt.expectedProxyIP, proxyIP)
			}
		})
	}
}

// Test SNI validation logic
func TestValidateSNI(t *testing.T) {
	tests := []struct {
		name            string
		clientIP        string
		requestedDomain string
		sniDomain       string
		expectValid     bool
	}{
		{
			name:            "exact match",
			clientIP:        "192.168.1.1",
			requestedDomain: "example.com",
			sniDomain:       "example.com",
			expectValid:     true,
		},
		{
			name:            "subdomain match",
			clientIP:        "192.168.1.1",
			requestedDomain: "example.com",
			sniDomain:       "www.example.com",
			expectValid:     true,
		},
		{
			name:            "parent domain match",
			clientIP:        "192.168.1.1",
			requestedDomain: "www.example.com",
			sniDomain:       "example.com",
			expectValid:     true,
		},
		{
			name:            "mismatch",
			clientIP:        "192.168.1.1",
			requestedDomain: "example.com",
			sniDomain:       "evil.com",
			expectValid:     false,
		},
		{
			name:            "empty requested domain",
			clientIP:        "192.168.1.1",
			requestedDomain: "",
			sniDomain:       "example.com",
			expectValid:     false,
		},
		{
			name:            "empty SNI domain",
			clientIP:        "192.168.1.1",
			requestedDomain: "example.com",
			sniDomain:       "",
			expectValid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateSNI(tt.clientIP, tt.requestedDomain, tt.sniDomain)

			if valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v", tt.expectValid, valid)
			}
		})
	}
}

// Test SNI extraction from ClientHello
func TestExtractSNIFromClientHello(t *testing.T) {
	tests := []struct {
		name        string
		clientHello []byte
		expectedSNI string
	}{
		{
			name: "valid ClientHello with SNI",
			clientHello: buildTestClientHello("example.com"),
			expectedSNI: "example.com",
		},
		{
			name:        "invalid ClientHello",
			clientHello: []byte{0x02, 0x00, 0x00, 0x00}, // ServerHello instead of ClientHello
			expectedSNI: "",
		},
		{
			name:        "empty data",
			clientHello: []byte{},
			expectedSNI: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni := extractSNIFromClientHello(tt.clientHello)

			if sni != tt.expectedSNI {
				t.Errorf("Expected SNI=%s, got %s", tt.expectedSNI, sni)
			}
		})
	}
}

// Test API endpoints
func TestAPISNIStats(t *testing.T) {
	// Setup test configuration
	originalConfig := sniInspectionConfig
	originalStats := sniStats
	defer func() {
		sniInspectionConfig = originalConfig
		sniStats = originalStats
	}()

	sniInspectionConfig = &SNIInspectionConfig{Enabled: true}
	sniStats = &SNIInspectionStats{
		TotalConnections:   10,
		ValidConnections:   8,
		InvalidConnections: 2,
		ClientStats:        make(map[string]*ClientSNIStats),
		DomainStats:        make(map[string]*DomainSNIStats),
	}

	req, err := http.NewRequest("GET", "/api/sni/stats", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handleAPISNIStats(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response SNIInspectionStats
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse JSON response: %v", err)
	}

	if response.TotalConnections != 10 {
		t.Errorf("Expected TotalConnections=10, got %d", response.TotalConnections)
	}
}

func TestAPISNIValidate(t *testing.T) {
	// Setup test configuration
	originalConfig := sniInspectionConfig
	defer func() { sniInspectionConfig = originalConfig }()

	sniInspectionConfig = &SNIInspectionConfig{
		Enabled:         true,
		StrictValidation: true,
		LogOnly:         false,
	}

	validRequest := `{
		"client_ip": "192.168.1.1",
		"requested_domain": "example.com",
		"sni_domain": "example.com"
	}`

	req, err := http.NewRequest("POST", "/api/sni/validate", strings.NewReader(validRequest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handleAPISNIValidate(rr, req, nil)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse JSON response: %v", err)
	}

	if response["is_valid"] != true {
		t.Errorf("Expected is_valid=true for matching domains")
	}
}

func TestAPISNIStatsDisabled(t *testing.T) {
	// Setup disabled configuration
	originalConfig := sniInspectionConfig
	defer func() { sniInspectionConfig = originalConfig }()

	sniInspectionConfig = nil

	req, err := http.NewRequest("GET", "/api/sni/stats", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handleAPISNIStats(rr, req, nil)

	if status := rr.Code; status != http.StatusNotImplemented {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotImplemented)
	}
}

// Test connection tracking
func TestTrackDNSRequest(t *testing.T) {
	// Setup test configuration
	originalConfig := sniInspectionConfig
	defer func() { sniInspectionConfig = originalConfig }()

	sniInspectionConfig = &SNIInspectionConfig{Enabled: true}

	// Clear any existing mappings
	sniDomainMappings = sync.Map{}

	// Track a DNS request
	trackDNSRequest("192.168.1.1", "example.com", "1.2.3.4")

	// Find the requested domain
	found := findRequestedDomain("192.168.1.1", "example.com")
	if found != "example.com" {
		t.Errorf("Expected to find requested domain 'example.com', got '%s'", found)
	}

	// Test subdomain lookup
	found = findRequestedDomain("192.168.1.1", "www.example.com")
	if found != "example.com" {
		t.Errorf("Expected to find parent domain 'example.com' for 'www.example.com', got '%s'", found)
	}

	// Test unknown domain
	found = findRequestedDomain("192.168.1.1", "unknown.com")
	if found != "unknown.com" {
		t.Errorf("Expected to return SNI domain 'unknown.com' for unknown mapping, got '%s'", found)
	}
}

// Helper functions

// buildTestClientHello creates a minimal ClientHello with SNI extension for testing
func buildTestClientHello(hostname string) []byte {
	// This is a simplified ClientHello structure with just the SNI extension
	// In real scenarios, this would be much more complex
	
	// Start with basic ClientHello structure
	hello := []byte{
		0x01,       // ClientHello message type
		0x00, 0x00, // Message length (to be filled)
		0x00,       // Message length continued
	}
	
	// Add protocol version (TLS 1.2)
	hello = append(hello, 0x03, 0x03)
	
	// Add 32-byte random
	random := make([]byte, 32)
	hello = append(hello, random...)
	
	// Add session ID length (0)
	hello = append(hello, 0x00)
	
	// Add cipher suites length (2) and a single cipher suite
	hello = append(hello, 0x00, 0x02, 0x00, 0x35)
	
	// Add compression methods length (1) and no compression
	hello = append(hello, 0x01, 0x00)
	
	// Build SNI extension
	sniExtension := buildSNIExtension(hostname)
	
	// Add extensions length
	extLength := len(sniExtension)
	hello = append(hello, byte(extLength>>8), byte(extLength))
	
	// Add SNI extension
	hello = append(hello, sniExtension...)
	
	// Update message length
	msgLen := len(hello) - 4
	hello[1] = byte(msgLen >> 16)
	hello[2] = byte(msgLen >> 8)
	hello[3] = byte(msgLen)
	
	return hello
}

// buildSNIExtension creates an SNI extension for testing
func buildSNIExtension(hostname string) []byte {
	// SNI extension type (0x0000)
	ext := []byte{0x00, 0x00}
	
	// Extension data length (to be filled)
	ext = append(ext, 0x00, 0x00)
	
	// Server name list length (to be filled)  
	ext = append(ext, 0x00, 0x00)
	
	// Server name type (0x00 for hostname)
	ext = append(ext, 0x00)
	
	// Server name length
	nameLen := len(hostname)
	ext = append(ext, byte(nameLen>>8), byte(nameLen))
	
	// Server name
	ext = append(ext, []byte(hostname)...)
	
	// Update lengths
	dataLen := len(ext) - 4
	ext[2] = byte(dataLen >> 8)
	ext[3] = byte(dataLen)
	
	listLen := len(ext) - 6
	ext[4] = byte(listLen >> 8)
	ext[5] = byte(listLen)
	
	return ext
}

// Integration test for complete SNI inspection flow
func TestSNIInspectionIntegration(t *testing.T) {
	// This test would ideally test the complete flow:
	// 1. DNS request with SNI inspection enabled
	// 2. Client connects to proxy IP
	// 3. SNI validation
	// 4. Connection proxying or blocking
	
	// For now, we'll test the configuration and decision logic
	originalConfig := sniInspectionConfig
	defer func() { sniInspectionConfig = originalConfig }()

	sniInspectionConfig = &SNIInspectionConfig{
		Enabled:          true,
		ProxyIPs:         []string{"10.0.0.1"},
		ProxyPorts:       []int{8443},
		StrictValidation: true,
		LogOnly:         false,
		ClientConfigs: []SNIClientConfig{
			{
				ClientPattern: "192.168.1.0/24",
				Enabled:       true,
			},
		},
	}

	// Test SNI inspection decision
	enabled, proxyIP := shouldUseSNIInspection("192.168.1.50", "example.com")
	if !enabled {
		t.Error("Expected SNI inspection to be enabled for 192.168.1.50")
	}
	if proxyIP != "10.0.0.1" {
		t.Errorf("Expected proxy IP 10.0.0.1, got %s", proxyIP)
	}

	// Test DNS request tracking
	trackDNSRequest("192.168.1.50", "example.com", "1.2.3.4")

	// Test SNI validation
	valid := validateSNI("192.168.1.50", "example.com", "example.com")
	if !valid {
		t.Error("Expected SNI validation to pass for matching domains")
	}

	invalid := validateSNI("192.168.1.50", "example.com", "evil.com")
	if invalid {
		t.Error("Expected SNI validation to fail for mismatched domains")
	}
}