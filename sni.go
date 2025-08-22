package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Global SNI inspection configuration and state
var (
	sniInspectionConfig *SNIInspectionConfig
	sniStats           *SNIInspectionStats
	activeConnections  sync.Map // map[connectionID]*SNIConnection
	sniStatsMutex      sync.RWMutex
	sniDomainMappings  sync.Map // map[clientIP]map[domain]resolvedIPs - tracks DNS requests for SNI validation
)

// loadSNIInspectionConfiguration loads SNI inspection configuration from JSON file
func loadSNIInspectionConfiguration(configPath string) (*SNIInspectionConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SNI inspection config file: %v", err)
	}

	var config SNIInspectionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse SNI inspection JSON config: %v", err)
	}

	// Set defaults
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 300
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 1000
	}
	if config.UpstreamTimeout == 0 {
		config.UpstreamTimeout = 30
	}
	if config.BufferSize == 0 {
		config.BufferSize = 32768
	}
	if config.StatsRetention == 0 {
		config.StatsRetention = 24
	}

	// Validate proxy IPs
	if len(config.ProxyIPs) == 0 {
		return nil, fmt.Errorf("proxy_ips cannot be empty")
	}
	for i, ip := range config.ProxyIPs {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid proxy IP at index %d: %s", i, ip)
		}
	}

	// Validate proxy ports
	if len(config.ProxyPorts) == 0 {
		return nil, fmt.Errorf("proxy_ports cannot be empty")
	}
	for i, port := range config.ProxyPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid proxy port at index %d: %d", i, port)
		}
	}

	// Validate TLS configuration if provided
	if config.CertFile != "" || config.KeyFile != "" {
		if config.CertFile == "" || config.KeyFile == "" {
			return nil, fmt.Errorf("both cert_file and key_file must be provided for TLS")
		}
		if _, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile); err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %v", err)
		}
	}

	// Validate client configurations
	for i, clientConfig := range config.ClientConfigs {
		if clientConfig.ClientPattern == "" {
			return nil, fmt.Errorf("client_configs[%d]: client_pattern cannot be empty", i)
		}
		if err := validateClientPattern(clientConfig.ClientPattern); err != nil {
			return nil, fmt.Errorf("client_configs[%d]: %v", i, err)
		}
		if clientConfig.ProxyIP != "" && net.ParseIP(clientConfig.ProxyIP) == nil {
			return nil, fmt.Errorf("client_configs[%d]: invalid proxy_ip: %s", i, clientConfig.ProxyIP)
		}
	}

	// Validate domain configurations
	for i, domainConfig := range config.DomainConfigs {
		if domainConfig.DomainPattern == "" {
			return nil, fmt.Errorf("domain_configs[%d]: domain_pattern cannot be empty", i)
		}
		if domainConfig.ProxyIP != "" && net.ParseIP(domainConfig.ProxyIP) == nil {
			return nil, fmt.Errorf("domain_configs[%d]: invalid proxy_ip: %s", i, domainConfig.ProxyIP)
		}
	}

	return &config, nil
}

// initializeSNIInspection initializes the SNI inspection system
func initializeSNIInspection() error {
	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		return nil
	}

	// Initialize statistics
	sniStats = &SNIInspectionStats{
		ClientStats: make(map[string]*ClientSNIStats),
		DomainStats: make(map[string]*DomainSNIStats),
		StartTime:   time.Now(),
	}

	log.Printf("SNI inspection initialized: %d proxy IPs, %d ports, %d client configs, %d domain configs",
		len(sniInspectionConfig.ProxyIPs),
		len(sniInspectionConfig.ProxyPorts),
		len(sniInspectionConfig.ClientConfigs),
		len(sniInspectionConfig.DomainConfigs))

	return nil
}

// shouldUseSNIInspection determines if SNI inspection should be used for a client/domain combination
func shouldUseSNIInspection(clientIP, domain string) (bool, string) {
	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		return false, ""
	}

	// Check client-specific configurations first (highest priority)
	for _, clientConfig := range sniInspectionConfig.ClientConfigs {
		if matchesClientPattern(clientIP, clientConfig.ClientPattern) && clientConfig.Enabled {
			proxyIP := clientConfig.ProxyIP
			if proxyIP == "" {
				proxyIP = sniInspectionConfig.ProxyIPs[0] // Use first proxy IP as default
			}
			return true, proxyIP
		}
	}

	// Check domain-specific configurations
	for _, domainConfig := range sniInspectionConfig.DomainConfigs {
		if matchesDomainPattern(domain, domainConfig.DomainPattern) && domainConfig.Enabled {
			proxyIP := domainConfig.ProxyIP
			if proxyIP == "" {
				proxyIP = sniInspectionConfig.ProxyIPs[0] // Use first proxy IP as default
			}
			return true, proxyIP
		}
	}

	return false, ""
}

// trackDNSRequest tracks a DNS request for later SNI validation
func trackDNSRequest(clientIP, domain, resolvedIP string) {
	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		return
	}

	// Load or create client mapping
	var clientMappings *sync.Map
	if mappings, exists := sniDomainMappings.Load(clientIP); exists {
		clientMappings = mappings.(*sync.Map)
	} else {
		clientMappings = &sync.Map{}
		sniDomainMappings.Store(clientIP, clientMappings)
	}

	// Store domain -> resolved IP mapping
	clientMappings.Store(domain, resolvedIP)

	if os.Getenv("DEBUG") != "" {
		log.Printf("SNI: Tracked DNS request %s -> %s for client %s", domain, resolvedIP, clientIP)
	}
}

// startSNIProxyServers starts SNI proxy servers on configured ports
func startSNIProxyServers() error {
	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		return nil
	}

	for _, port := range sniInspectionConfig.ProxyPorts {
		go startSNIProxyServer(port)
	}

	return nil
}

// startSNIProxyServer starts a single SNI proxy server on the specified port
func startSNIProxyServer(port int) {
	address := fmt.Sprintf(":%d", port)
	
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Printf("SNI proxy server failed to listen on port %d: %v", port, err)
		return
	}
	defer listener.Close()

	log.Printf("SNI proxy server started on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SNI proxy server failed to accept connection on port %d: %v", port, err)
			continue
		}

		go handleSNIConnection(conn, port)
	}
}

// handleSNIConnection handles a single SNI inspection connection
func handleSNIConnection(clientConn net.Conn, proxyPort int) {
	defer clientConn.Close()

	// Get client IP
	clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()

	// Generate unique connection ID
	connectionID := generateConnectionID()

	// Create connection tracking object
	sniConnection := &SNIConnection{
		ConnectionID: connectionID,
		ClientIP:     clientIP,
		ProxyPort:    proxyPort,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Status:       "connecting",
	}

	// Store active connection
	activeConnections.Store(connectionID, sniConnection)
	defer activeConnections.Delete(connectionID)

	// Set connection timeout
	if sniInspectionConfig.ConnectionTimeout > 0 {
		clientConn.SetDeadline(time.Now().Add(time.Duration(sniInspectionConfig.ConnectionTimeout) * time.Second))
	}

	// Read TLS ClientHello to extract SNI
	sniDomain, err := extractSNIFromConnection(clientConn)
	if err != nil {
		log.Printf("SNI extraction failed for connection %s from %s: %v", connectionID, clientIP, err)
		updateSNIStats("tls_errors", 1)
		sniConnection.Status = "error"
		return
	}

	sniConnection.SNIDomain = sniDomain
	sniConnection.Status = "validating"

	// Find the requested domain for this client
	requestedDomain := findRequestedDomain(clientIP, sniDomain)
	sniConnection.RequestedDomain = requestedDomain

	// Validate SNI
	isValid := validateSNI(clientIP, requestedDomain, sniDomain)
	sniConnection.IsValid = isValid

	if os.Getenv("DEBUG") != "" {
		log.Printf("SNI connection %s: client=%s, requested=%s, sni=%s, valid=%v",
			connectionID, clientIP, requestedDomain, sniDomain, isValid)
	}

	// Update statistics
	updateSNIConnectionStats(clientIP, requestedDomain, sniDomain, isValid)

	// Handle validation result
	if !isValid {
		handleSNIMismatch(sniConnection)
		if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
			log.Printf("SNI BLOCK: Connection %s blocked due to SNI mismatch (requested: %s, sni: %s)",
				connectionID, requestedDomain, sniDomain)
			sniConnection.Status = "blocked"
			return
		}
	}

	// If we reach here, connection is valid or we're in log-only mode
	sniConnection.Status = "active"

	// Proxy the connection to the real destination
	err = proxyConnection(clientConn, sniDomain, sniConnection)
	if err != nil {
		log.Printf("SNI proxy failed for connection %s: %v", connectionID, err)
		sniConnection.Status = "error"
		return
	}

	sniConnection.Status = "closed"
}

// extractSNIFromConnection extracts SNI from TLS ClientHello
func extractSNIFromConnection(conn net.Conn) (string, error) {
	// Set handshake timeout
	if sniInspectionConfig.HandshakeTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(sniInspectionConfig.HandshakeTimeout) * time.Second))
	}

	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS record header: %v", err)
	}

	// Verify this is a TLS handshake record
	if header[0] != 0x16 { // TLS Handshake
		return "", fmt.Errorf("not a TLS handshake record (type: 0x%02x)", header[0])
	}

	// Get record length
	recordLength := int(header[3])<<8 + int(header[4])
	if recordLength > 16384 { // TLS record size limit
		return "", fmt.Errorf("TLS record too large: %d bytes", recordLength)
	}

	// Read the complete TLS record
	record := make([]byte, recordLength)
	_, err = io.ReadFull(conn, record)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS record: %v", err)
	}

	// Parse ClientHello to extract SNI
	sniDomain := extractSNIFromClientHello(record)
	if sniDomain == "" {
		return "", fmt.Errorf("no SNI found in ClientHello")
	}

	return sniDomain, nil
}

// extractSNIFromClientHello parses ClientHello message to extract SNI
func extractSNIFromClientHello(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	// Verify this is a ClientHello message
	if data[0] != 0x01 { // ClientHello
		return ""
	}

	// Parse ClientHello structure
	offset := 4 // Skip handshake header

	// Skip protocol version (2 bytes)
	if len(data) < offset+2 {
		return ""
	}
	offset += 2

	// Skip random (32 bytes)
	if len(data) < offset+32 {
		return ""
	}
	offset += 32

	// Skip session ID
	if len(data) < offset+1 {
		return ""
	}
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength
	if len(data) < offset {
		return ""
	}

	// Skip cipher suites
	if len(data) < offset+2 {
		return ""
	}
	cipherSuitesLength := int(data[offset])<<8 + int(data[offset+1])
	offset += 2 + cipherSuitesLength
	if len(data) < offset {
		return ""
	}

	// Skip compression methods
	if len(data) < offset+1 {
		return ""
	}
	compressionLength := int(data[offset])
	offset += 1 + compressionLength
	if len(data) < offset {
		return ""
	}

	// Parse extensions
	if len(data) < offset+2 {
		return ""
	}
	extensionsLength := int(data[offset])<<8 + int(data[offset+1])
	offset += 2

	// Look for SNI extension (type 0x0000)
	extensionsEnd := offset + extensionsLength
	for offset < extensionsEnd-4 {
		if len(data) < offset+4 {
			return ""
		}

		extensionType := int(data[offset])<<8 + int(data[offset+1])
		extensionLength := int(data[offset+2])<<8 + int(data[offset+3])
		offset += 4

		if extensionType == 0x0000 { // SNI extension
			return parseSNIExtension(data[offset : offset+extensionLength])
		}

		offset += extensionLength
	}

	return ""
}

// parseSNIExtension parses the SNI extension to extract domain name
func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Skip server name list length (2 bytes)
	offset := 2

	// Parse server name entries
	for offset < len(data)-3 {
		nameType := data[offset]
		if nameType != 0x00 { // hostname
			return ""
		}
		offset++

		nameLength := int(data[offset])<<8 + int(data[offset+1])
		offset += 2

		if offset+nameLength > len(data) {
			return ""
		}

		hostname := string(data[offset : offset+nameLength])
		return hostname
	}

	return ""
}

// findRequestedDomain finds the domain that was originally requested via DNS for this SNI domain
func findRequestedDomain(clientIP, sniDomain string) string {
	if mappings, exists := sniDomainMappings.Load(clientIP); exists {
		clientMappings := mappings.(*sync.Map)
		
		// First try exact match
		if _, exists := clientMappings.Load(sniDomain); exists {
			return sniDomain
		}
		
		// Try to find a parent domain match
		var foundDomain string
		clientMappings.Range(func(key, value interface{}) bool {
			domain := key.(string)
			// Check if SNI domain is a subdomain of requested domain
			if strings.HasSuffix(sniDomain, "."+domain) || domain == sniDomain {
				foundDomain = domain
				return false // Stop iteration
			}
			return true // Continue iteration
		})
		
		if foundDomain != "" {
			return foundDomain
		}
	}

	// If no mapping found, assume SNI domain is the requested domain
	return sniDomain
}

// validateSNI validates that the SNI matches the originally requested domain
func validateSNI(clientIP, requestedDomain, sniDomain string) bool {
	if requestedDomain == "" || sniDomain == "" {
		return false
	}

	// Exact match
	if requestedDomain == sniDomain {
		return true
	}

	// Check if SNI is a subdomain of requested domain
	if strings.HasSuffix(sniDomain, "."+requestedDomain) {
		return true
	}

	// Check if requested domain is a subdomain of SNI (for CDNs, etc.)
	if strings.HasSuffix(requestedDomain, "."+sniDomain) {
		return true
	}

	return false
}

// handleSNIMismatch handles SNI validation mismatch
func handleSNIMismatch(connection *SNIConnection) {
	// Create mismatch event
	event := &SNIMismatchEvent{
		EventID:         generateConnectionID(),
		Timestamp:       time.Now(),
		ClientIP:        connection.ClientIP,
		RequestedDomain: connection.RequestedDomain,
		SNIDomain:       connection.SNIDomain,
		ProxyPort:       connection.ProxyPort,
		ConnectionID:    connection.ConnectionID,
	}

	if sniInspectionConfig.LogOnly {
		event.Action = "logged"
		log.Printf("SNI MISMATCH LOG: %s requested %s but connected with SNI %s (connection: %s)",
			connection.ClientIP, connection.RequestedDomain, connection.SNIDomain, connection.ConnectionID)
	} else {
		event.Action = "blocked"
		log.Printf("SNI MISMATCH BLOCK: %s requested %s but connected with SNI %s (connection: %s)",
			connection.ClientIP, connection.RequestedDomain, connection.SNIDomain, connection.ConnectionID)
	}

	// TODO: Store mismatch events in Redis for API access
}

// proxyConnection proxies the validated connection to the real destination
func proxyConnection(clientConn net.Conn, targetDomain string, sniConnection *SNIConnection) error {
	// Connect to real destination (port 443 for HTTPS)
	targetAddr := fmt.Sprintf("%s:443", targetDomain)
	
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(sniInspectionConfig.UpstreamTimeout)*time.Second)
	defer cancel()

	var d net.Dialer
	upstreamConn, err := d.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to upstream %s: %v", targetAddr, err)
	}
	defer upstreamConn.Close()

	// Start bidirectional data copying
	done := make(chan error, 2)

	// Client -> Upstream
	go func() {
		bytes, err := io.Copy(upstreamConn, clientConn)
		sniConnection.BytesUpstream += bytes
		done <- err
	}()

	// Upstream -> Client
	go func() {
		bytes, err := io.Copy(clientConn, upstreamConn)
		sniConnection.BytesDownstream += bytes
		done <- err
	}()

	// Wait for either direction to complete
	err = <-done
	if err != nil && err != io.EOF {
		return fmt.Errorf("proxy error: %v", err)
	}

	return nil
}

// updateSNIConnectionStats updates SNI connection statistics
func updateSNIConnectionStats(clientIP, requestedDomain, sniDomain string, isValid bool) {
	sniStatsMutex.Lock()
	defer sniStatsMutex.Unlock()

	// Update global stats
	sniStats.TotalConnections++
	if isValid {
		sniStats.ValidConnections++
	} else {
		sniStats.InvalidConnections++
		if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
			sniStats.BlockedConnections++
		}
	}

	// Update client stats
	if clientStats, exists := sniStats.ClientStats[clientIP]; exists {
		clientStats.TotalConnections++
		if isValid {
			clientStats.ValidConnections++
		} else {
			clientStats.InvalidConnections++
			if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
				clientStats.BlockedConnections++
			}
		}
		clientStats.LastConnection = time.Now()
	} else {
		clientStats := &ClientSNIStats{
			ClientIP:         clientIP,
			TotalConnections: 1,
			FirstConnection:  time.Now(),
			LastConnection:   time.Now(),
		}
		if isValid {
			clientStats.ValidConnections = 1
		} else {
			clientStats.InvalidConnections = 1
			if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
				clientStats.BlockedConnections = 1
			}
		}
		sniStats.ClientStats[clientIP] = clientStats
	}

	// Update domain stats
	domain := requestedDomain
	if domain == "" {
		domain = sniDomain
	}
	
	if domainStats, exists := sniStats.DomainStats[domain]; exists {
		domainStats.TotalConnections++
		if isValid {
			domainStats.ValidConnections++
		} else {
			domainStats.InvalidConnections++
			if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
				domainStats.BlockedConnections++
			}
		}
		domainStats.LastConnection = time.Now()
	} else {
		domainStats := &DomainSNIStats{
			Domain:           domain,
			TotalConnections: 1,
			FirstConnection:  time.Now(),
			LastConnection:   time.Now(),
		}
		if isValid {
			domainStats.ValidConnections = 1
		} else {
			domainStats.InvalidConnections = 1
			if sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly {
				domainStats.BlockedConnections = 1
			}
		}
		sniStats.DomainStats[domain] = domainStats
	}

	sniStats.LastUpdated = time.Now()
}

// updateSNIStats updates specific SNI statistics
func updateSNIStats(statType string, delta int64) {
	sniStatsMutex.Lock()
	defer sniStatsMutex.Unlock()

	switch statType {
	case "tls_errors":
		sniStats.TLSErrors += delta
	case "timeout_errors":
		sniStats.TimeoutErrors += delta
	}

	sniStats.LastUpdated = time.Now()
}

// generateConnectionID generates a unique connection identifier
func generateConnectionID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getSNIInspectionStats returns current SNI inspection statistics
func getSNIInspectionStats() *SNIInspectionStats {
	if sniStats == nil {
		return nil
	}

	sniStatsMutex.RLock()
	defer sniStatsMutex.RUnlock()

	// Count active connections
	activeCount := 0
	activeConnections.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	sniStats.ActiveConnections = activeCount

	// Return copy of stats
	statsCopy := *sniStats
	statsCopy.ClientStats = make(map[string]*ClientSNIStats)
	for k, v := range sniStats.ClientStats {
		clientStatsCopy := *v
		statsCopy.ClientStats[k] = &clientStatsCopy
	}
	statsCopy.DomainStats = make(map[string]*DomainSNIStats)
	for k, v := range sniStats.DomainStats {
		domainStatsCopy := *v
		statsCopy.DomainStats[k] = &domainStatsCopy
	}

	return &statsCopy
}

// getActiveSNIConnections returns current active SNI connections
func getActiveSNIConnections() []*SNIConnection {
	var connections []*SNIConnection
	
	activeConnections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*SNIConnection); ok {
			connCopy := *conn
			connections = append(connections, &connCopy)
		}
		return true
	})
	
	return connections
}