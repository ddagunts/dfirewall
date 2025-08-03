package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"github.com/redis/go-redis/v9"
)

// Global SSH log monitoring state
var (
	sshLogConfig    *SSHLogConfig
	sshMonitors     = make(map[string]*SSHMonitor)
	sshMonitorMutex sync.RWMutex
)

// SSHMonitor represents an active SSH log monitoring session
type SSHMonitor struct {
	config      *SSHServer
	client      *ssh.Client
	session     *ssh.Session
	logFiles    map[string]*LogFileMonitor
	ctx         context.Context
	cancel      context.CancelFunc
	status      *SSHServerStatus
	redisClient *redis.Client
	mutex       sync.RWMutex
}

// LogFileMonitor represents an active log file monitoring session
type LogFileMonitor struct {
	config      *SSHLogFile
	reader      io.Reader
	scanner     *bufio.Scanner
	ipRegex     *regexp.Regexp
	domainRegex *regexp.Regexp
	includeRegex *regexp.Regexp
	excludeRegex *regexp.Regexp
	linesProcessed int64
	ipsExtracted   int64
	domainsExtracted int64
	lastActivity   time.Time
	mutex          sync.RWMutex
}

// loadSSHLogConfiguration loads SSH log monitoring configuration
func loadSSHLogConfiguration(configPath string) (*SSHLogConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH log config file: %v", err)
	}
	
	var config SSHLogConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse SSH log JSON config: %v", err)
	}
	
	// Validate configuration
	if err := validateSSHLogConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid SSH log configuration: %v", err)
	}
	
	// Apply defaults
	applySSHLogDefaults(&config)
	
	log.Printf("Loaded SSH log configuration with %d servers", len(config.Servers))
	return &config, nil
}

// validateSSHLogConfig validates SSH log monitoring configuration
func validateSSHLogConfig(config *SSHLogConfig) error {
	if len(config.Servers) == 0 {
		return fmt.Errorf("no SSH servers configured")
	}
	
	for i, server := range config.Servers {
		if err := validateSSHServer(&server); err != nil {
			return fmt.Errorf("server %d (%s): %v", i, server.Name, err)
		}
	}
	
	return nil
}

// validateSSHServer validates a single SSH server configuration
func validateSSHServer(server *SSHServer) error {
	if server.Name == "" {
		return fmt.Errorf("server name is required")
	}
	
	if server.Host == "" {
		return fmt.Errorf("server host is required")
	}
	
	if server.Username == "" {
		return fmt.Errorf("server username is required")
	}
	
	// Validate authentication method
	switch server.AuthMethod {
	case "password":
		if server.Password == "" {
			return fmt.Errorf("password is required for password authentication")
		}
	case "key":
		if server.PrivateKeyPath == "" && server.PrivateKeyData == "" {
			return fmt.Errorf("private key path or data is required for key authentication")
		}
	case "agent":
		// SSH agent authentication requires no additional validation
	default:
		return fmt.Errorf("invalid auth method: %s (must be password, key, or agent)", server.AuthMethod)
	}
	
	// Validate log files
	if len(server.LogFiles) == 0 {
		return fmt.Errorf("no log files configured")
	}
	
	for j, logFile := range server.LogFiles {
		if err := validateSSHLogFile(&logFile); err != nil {
			return fmt.Errorf("log file %d: %v", j, err)
		}
	}
	
	return nil
}

// validateSSHLogFile validates a single log file configuration
func validateSSHLogFile(logFile *SSHLogFile) error {
	if logFile.Path == "" {
		return fmt.Errorf("log file path is required")
	}
	
	if logFile.IPRegex == "" {
		return fmt.Errorf("IP regex pattern is required")
	}
	
	// Test regex patterns
	if _, err := regexp.Compile(logFile.IPRegex); err != nil {
		return fmt.Errorf("invalid IP regex pattern: %v", err)
	}
	
	if logFile.DomainRegex != "" {
		if _, err := regexp.Compile(logFile.DomainRegex); err != nil {
			return fmt.Errorf("invalid domain regex pattern: %v", err)
		}
	}
	
	if logFile.IncludeFilter != "" {
		if _, err := regexp.Compile(logFile.IncludeFilter); err != nil {
			return fmt.Errorf("invalid include filter regex: %v", err)
		}
	}
	
	if logFile.ExcludeFilter != "" {
		if _, err := regexp.Compile(logFile.ExcludeFilter); err != nil {
			return fmt.Errorf("invalid exclude filter regex: %v", err)
		}
	}
	
	return nil
}

// applySSHLogDefaults applies default values to SSH log configuration
func applySSHLogDefaults(config *SSHLogConfig) {
	defaults := &config.GlobalDefaults
	
	// Set sensible defaults
	if defaults.Port == 0 {
		defaults.Port = 22
	}
	if defaults.ConnectionTimeout == 0 {
		defaults.ConnectionTimeout = 30
	}
	if defaults.KeepAlive == 0 {
		defaults.KeepAlive = 30
	}
	if defaults.MaxRetries == 0 {
		defaults.MaxRetries = 3
	}
	if defaults.AuthMethod == "" {
		defaults.AuthMethod = "key"
	}
	if defaults.BufferSize == 0 {
		defaults.BufferSize = 4096
	}
	if defaults.MaxLineLength == 0 {
		defaults.MaxLineLength = 1024
	}
	if defaults.ProcessInterval == 0 {
		defaults.ProcessInterval = 1
	}
	if defaults.DefaultTTL == 0 {
		defaults.DefaultTTL = 3600
	}
	
	// Apply defaults to servers
	for i := range config.Servers {
		server := &config.Servers[i]
		
		if server.Port == 0 {
			server.Port = defaults.Port
		}
		if server.ConnectionTimeout == 0 {
			server.ConnectionTimeout = defaults.ConnectionTimeout
		}
		if server.KeepAlive == 0 {
			server.KeepAlive = defaults.KeepAlive
		}
		if server.MaxRetries == 0 {
			server.MaxRetries = defaults.MaxRetries
		}
		if server.AuthMethod == "" {
			server.AuthMethod = defaults.AuthMethod
		}
		if !server.StrictHostKeyChecking {
			server.StrictHostKeyChecking = defaults.StrictHostKeyChecking
		}
		
		// Apply defaults to log files
		for j := range server.LogFiles {
			logFile := &server.LogFiles[j]
			
			if logFile.BufferSize == 0 {
				logFile.BufferSize = defaults.BufferSize
			}
			if logFile.MaxLineLength == 0 {
				logFile.MaxLineLength = defaults.MaxLineLength
			}
			if logFile.ProcessInterval == 0 {
				logFile.ProcessInterval = defaults.ProcessInterval
			}
			if logFile.DefaultTTL == 0 {
				logFile.DefaultTTL = defaults.DefaultTTL
			}
		}
	}
	
	// Set retry config defaults
	retry := &config.RetryConfig
	if retry.InitialDelay == 0 {
		retry.InitialDelay = 5
	}
	if retry.MaxDelay == 0 {
		retry.MaxDelay = 300
	}
	if retry.BackoffMultiplier == 0 {
		retry.BackoffMultiplier = 2.0
	}
	if retry.MaxReconnectAttempts == 0 {
		retry.MaxReconnectAttempts = 10
	}
	if retry.ReconnectInterval == 0 {
		retry.ReconnectInterval = 60
	}
	if retry.HealthCheckInterval == 0 {
		retry.HealthCheckInterval = 300
	}
}

// initializeSSHLogMonitoring initializes SSH log monitoring system
func initializeSSHLogMonitoring(redisClient *redis.Client) error {
	if sshLogConfig == nil || !sshLogConfig.Enabled {
		return nil
	}
	
	log.Printf("Initializing SSH log monitoring with %d servers", len(sshLogConfig.Servers))
	
	// Start monitoring each enabled server
	for _, serverConfig := range sshLogConfig.Servers {
		if !serverConfig.Enabled {
			log.Printf("Skipping disabled SSH server: %s", serverConfig.Name)
			continue
		}
		
		monitor, err := createSSHMonitor(&serverConfig, redisClient)
		if err != nil {
			log.Printf("Failed to create SSH monitor for %s: %v", serverConfig.Name, err)
			continue
		}
		
		sshMonitorMutex.Lock()
		sshMonitors[serverConfig.Name] = monitor
		sshMonitorMutex.Unlock()
		
		// Start monitoring in background
		go monitor.start()
		
		log.Printf("Started SSH log monitoring for server: %s (%s)", serverConfig.Name, serverConfig.Host)
	}
	
	return nil
}

// createSSHMonitor creates a new SSH monitor for a server
func createSSHMonitor(config *SSHServer, redisClient *redis.Client) (*SSHMonitor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	status := &SSHServerStatus{
		Name:             config.Name,
		Host:             config.Host,
		Connected:        false,
		LogFilesActive:   0,
		LinesProcessed:   0,
		IPsExtracted:     0,
		DomainsExtracted: 0,
		LastActivity:     time.Now(),
	}
	
	monitor := &SSHMonitor{
		config:      config,
		logFiles:    make(map[string]*LogFileMonitor),
		ctx:         ctx,
		cancel:      cancel,
		status:      status,
		redisClient: redisClient,
	}
	
	return monitor, nil
}

// start starts the SSH monitor
func (m *SSHMonitor) start() {
	defer m.cancel()
	
	retryDelay := time.Duration(sshLogConfig.RetryConfig.InitialDelay) * time.Second
	maxDelay := time.Duration(sshLogConfig.RetryConfig.MaxDelay) * time.Second
	backoffMultiplier := sshLogConfig.RetryConfig.BackoffMultiplier
	maxReconnectAttempts := sshLogConfig.RetryConfig.MaxReconnectAttempts
	
	attemptCount := 0
	
	for {
		select {
		case <-m.ctx.Done():
			log.Printf("SSH monitor for %s stopped", m.config.Name)
			return
		default:
		}
		
		// Try to connect and monitor
		err := m.connectAndMonitor()
		if err != nil {
			attemptCount++
			m.mutex.Lock()
			m.status.LastError = err.Error()
			m.status.Connected = false
			m.mutex.Unlock()
			
			if attemptCount >= maxReconnectAttempts {
				log.Printf("SSH monitor for %s: max reconnection attempts reached, stopping", m.config.Name)
				return
			}
			
			log.Printf("SSH monitor for %s failed (attempt %d/%d): %v, retrying in %v", 
				m.config.Name, attemptCount, maxReconnectAttempts, err, retryDelay)
			
			// Exponential backoff
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(retryDelay):
			}
			
			retryDelay = time.Duration(float64(retryDelay) * backoffMultiplier)
			if retryDelay > maxDelay {
				retryDelay = maxDelay
			}
		} else {
			// Successful connection, reset retry delay
			retryDelay = time.Duration(sshLogConfig.RetryConfig.InitialDelay) * time.Second
			attemptCount = 0
		}
	}
}

// connectAndMonitor establishes SSH connection and starts log monitoring
func (m *SSHMonitor) connectAndMonitor() error {
	// Create SSH client configuration
	sshConfig, err := m.createSSHConfig()
	if err != nil {
		return fmt.Errorf("failed to create SSH config: %v", err)
	}
	
	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	defer client.Close()
	
	m.mutex.Lock()
	m.client = client
	m.status.Connected = true
	m.status.LastConnected = time.Now()
	m.status.LastError = ""
	m.mutex.Unlock()
	
	log.Printf("SSH connected to %s (%s)", m.config.Name, m.config.Host)
	
	// Start monitoring log files
	return m.monitorLogFiles()
}

// createSSHConfig creates SSH client configuration
func (m *SSHMonitor) createSSHConfig() (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:    m.config.Username,
		Timeout: time.Duration(m.config.ConnectionTimeout) * time.Second,
	}
	
	// Configure authentication
	switch m.config.AuthMethod {
	case "password":
		config.Auth = []ssh.AuthMethod{
			ssh.Password(m.config.Password),
		}
	case "key":
		authMethod, err := m.createKeyAuth()
		if err != nil {
			return nil, fmt.Errorf("failed to create key authentication: %v", err)
		}
		config.Auth = []ssh.AuthMethod{authMethod}
	case "agent":
		// TODO: Implement SSH agent authentication
		return nil, fmt.Errorf("SSH agent authentication not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", m.config.AuthMethod)
	}
	
	// Configure host key verification
	if m.config.StrictHostKeyChecking {
		if m.config.KnownHostsFile != "" {
			hostKeyCallback, err := createKnownHostsCallback(m.config.KnownHostsFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load known hosts: %v", err)
			}
			config.HostKeyCallback = hostKeyCallback
		} else if m.config.HostKeyFingerprint != "" {
			config.HostKeyCallback = createFingerprintCallback(m.config.HostKeyFingerprint)
		} else {
			return nil, fmt.Errorf("strict host key checking enabled but no known hosts file or fingerprint provided")
		}
	} else {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	
	return config, nil
}

// createKeyAuth creates SSH key authentication method
func (m *SSHMonitor) createKeyAuth() (ssh.AuthMethod, error) {
	var keyData []byte
	var err error
	
	if m.config.PrivateKeyData != "" {
		// Decode base64 key data
		keyData, err = base64.StdEncoding.DecodeString(m.config.PrivateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key data: %v", err)
		}
	} else if m.config.PrivateKeyPath != "" {
		// Read key from file
		keyData, err = os.ReadFile(m.config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %v", err)
		}
	} else {
		return nil, fmt.Errorf("no private key data or path provided")
	}
	
	var signer ssh.Signer
	if m.config.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(m.config.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	
	return ssh.PublicKeys(signer), nil
}

// createKnownHostsCallback creates host key verification callback from known_hosts file
func createKnownHostsCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	return ssh.ReadKnownHostsFile(knownHostsFile)
}

// createFingerprintCallback creates host key verification callback from fingerprint
func createFingerprintCallback(expectedFingerprint string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if fingerprint != expectedFingerprint {
			return fmt.Errorf("host key fingerprint mismatch: expected %s, got %s", expectedFingerprint, fingerprint)
		}
		return nil
	}
}

// monitorLogFiles starts monitoring all configured log files
func (m *SSHMonitor) monitorLogFiles() error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.config.LogFiles))
	
	// Start monitoring each enabled log file
	for _, logFileConfig := range m.config.LogFiles {
		if !logFileConfig.Enabled {
			continue
		}
		
		wg.Add(1)
		go func(config SSHLogFile) {
			defer wg.Done()
			
			monitor, err := m.createLogFileMonitor(&config)
			if err != nil {
				errChan <- fmt.Errorf("failed to create log monitor for %s: %v", config.Path, err)
				return
			}
			
			m.mutex.Lock()
			m.logFiles[config.Path] = monitor
			m.status.LogFilesActive++
			m.mutex.Unlock()
			
			// Start monitoring this log file
			err = monitor.start(m)
			if err != nil {
				errChan <- fmt.Errorf("log monitor for %s failed: %v", config.Path, err)
			}
		}(logFileConfig)
	}
	
	// Wait for all log monitors to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()
	
	// Collect any errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
		log.Printf("SSH log monitor error: %v", err)
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("log monitoring errors: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

// createLogFileMonitor creates a log file monitor
func (m *SSHMonitor) createLogFileMonitor(config *SSHLogFile) (*LogFileMonitor, error) {
	monitor := &LogFileMonitor{
		config:       config,
		lastActivity: time.Now(),
	}
	
	// Compile regex patterns
	var err error
	monitor.ipRegex, err = regexp.Compile(config.IPRegex)
	if err != nil {
		return nil, fmt.Errorf("failed to compile IP regex: %v", err)
	}
	
	if config.DomainRegex != "" {
		monitor.domainRegex, err = regexp.Compile(config.DomainRegex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile domain regex: %v", err)
		}
	}
	
	if config.IncludeFilter != "" {
		monitor.includeRegex, err = regexp.Compile(config.IncludeFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to compile include filter regex: %v", err)
		}
	}
	
	if config.ExcludeFilter != "" {
		monitor.excludeRegex, err = regexp.Compile(config.ExcludeFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to compile exclude filter regex: %v", err)
		}
	}
	
	return monitor, nil
}

// start starts monitoring a log file
func (lm *LogFileMonitor) start(sshMonitor *SSHMonitor) error {
	// Create SSH session for this log file
	session, err := sshMonitor.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()
	
	// Determine tail command based on configuration
	tailCmd := "tail"
	if lm.config.FollowRotation {
		tailCmd += " -F" // Follow with retry and rotation handling
	} else {
		tailCmd += " -f" // Follow without rotation handling
	}
	
	if lm.config.StartFromEnd {
		tailCmd += " -n 0" // Start from end of file
	}
	
	tailCmd += " " + lm.config.Path
	
	log.Printf("Starting log monitor for %s with command: %s", lm.config.Path, tailCmd)
	
	// Start the tail command
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	
	err = session.Start(tailCmd)
	if err != nil {
		return fmt.Errorf("failed to start tail command: %v", err)
	}
	
	// Create buffered reader
	lm.reader = stdout
	lm.scanner = bufio.NewScanner(lm.reader)
	
	// Set buffer size if configured
	if lm.config.BufferSize > 0 {
		buf := make([]byte, lm.config.BufferSize)
		lm.scanner.Buffer(buf, lm.config.BufferSize)
	}
	
	// Process log lines
	for lm.scanner.Scan() {
		select {
		case <-sshMonitor.ctx.Done():
			return nil
		default:
		}
		
		line := lm.scanner.Text()
		
		// Check line length
		if len(line) > lm.config.MaxLineLength {
			if os.Getenv("DEBUG") != "" {
				log.Printf("Skipping oversized line (%d chars) from %s", len(line), lm.config.Path)
			}
			continue
		}
		
		// Apply filters
		if !lm.shouldProcessLine(line) {
			continue
		}
		
		// Process the line
		lm.processLogLine(line, sshMonitor)
		
		lm.mutex.Lock()
		lm.linesProcessed++
		lm.lastActivity = time.Now()
		lm.mutex.Unlock()
		
		// Update server status
		sshMonitor.mutex.Lock()
		sshMonitor.status.LinesProcessed++
		sshMonitor.status.LastActivity = time.Now()
		sshMonitor.mutex.Unlock()
	}
	
	// Check for scanner errors
	if err := lm.scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %v", err)
	}
	
	// Wait for session to complete
	return session.Wait()
}

// shouldProcessLine checks if a log line should be processed based on filters
func (lm *LogFileMonitor) shouldProcessLine(line string) bool {
	// Check include filter
	if lm.includeRegex != nil && !lm.includeRegex.MatchString(line) {
		return false
	}
	
	// Check exclude filter
	if lm.excludeRegex != nil && lm.excludeRegex.MatchString(line) {
		return false
	}
	
	return true
}

// processLogLine processes a single log line and extracts IPs/domains
func (lm *LogFileMonitor) processLogLine(line string, sshMonitor *SSHMonitor) {
	entry := &SSHLogEntry{
		ServerName: sshMonitor.config.Name,
		LogFile:    lm.config.Path,
		Line:       line,
		Timestamp:  time.Now(),
		TTL:        lm.config.DefaultTTL,
	}
	
	// Extract IPs using regex
	ipMatches := lm.ipRegex.FindAllString(line, -1)
	if len(ipMatches) > 0 {
		entry.ExtractedIPs = removeDuplicates(ipMatches)
		
		lm.mutex.Lock()
		lm.ipsExtracted += int64(len(entry.ExtractedIPs))
		lm.mutex.Unlock()
		
		sshMonitor.mutex.Lock()
		sshMonitor.status.IPsExtracted += int64(len(entry.ExtractedIPs))
		sshMonitor.mutex.Unlock()
		
		if os.Getenv("DEBUG") != "" {
			log.Printf("Extracted IPs from %s: %v", lm.config.Path, entry.ExtractedIPs)
		}
	}
	
	// Extract domains using regex if configured
	if lm.domainRegex != nil {
		domainMatches := lm.domainRegex.FindAllString(line, -1)
		if len(domainMatches) > 0 {
			entry.ExtractedDomains = removeDuplicates(domainMatches)
			
			lm.mutex.Lock()
			lm.domainsExtracted += int64(len(entry.ExtractedDomains))
			lm.mutex.Unlock()
			
			sshMonitor.mutex.Lock()
			sshMonitor.status.DomainsExtracted += int64(len(entry.ExtractedDomains))
			sshMonitor.mutex.Unlock()
			
			if os.Getenv("DEBUG") != "" {
				log.Printf("Extracted domains from %s: %v", lm.config.Path, entry.ExtractedDomains)
			}
		}
	}
	
	// Process extracted data if we found anything
	if len(entry.ExtractedIPs) > 0 || len(entry.ExtractedDomains) > 0 {
		lm.processExtractedData(entry, sshMonitor)
	}
}

// processExtractedData processes extracted IPs and domains
func (lm *LogFileMonitor) processExtractedData(entry *SSHLogEntry, sshMonitor *SSHMonitor) {
	ctx := context.Background()
	
	// Determine client IP for firewall rules
	clientIP := lm.config.ClientIPOverride
	if clientIP == "" && lm.config.TreatAsClient && len(entry.ExtractedIPs) > 0 {
		clientIP = entry.ExtractedIPs[0] // Use first extracted IP as client
	}
	if clientIP == "" {
		clientIP = sshMonitor.config.Host // Use SSH server IP as fallback
	}
	
	entry.ClientIP = clientIP
	
	// Process extracted IPs
	for _, ip := range entry.ExtractedIPs {
		if !validateIP(ip) {
			log.Printf("Skipping invalid IP from SSH log: %s", ip)
			continue
		}
		
		// Determine domain for this IP
		domain := lm.config.DefaultDomain
		if len(entry.ExtractedDomains) > 0 {
			domain = entry.ExtractedDomains[0] // Use first extracted domain
		}
		if domain == "" {
			domain = fmt.Sprintf("ssh-log.%s", sanitizeForDomain(lm.config.Path))
		}
		
		entry.Domain = domain
		
		// Create Redis key for this rule
		key := fmt.Sprintf("rules:%s|%s|%s", clientIP, ip, domain)
		entry.RedisKeys = append(entry.RedisKeys, key)
		
		// Check if this is a new rule
		exists, err := sshMonitor.redisClient.Exists(ctx, key).Result()
		if err != nil {
			log.Printf("Error checking Redis key existence for SSH log entry: %v", err)
			continue
		}
		
		isNewRule := exists == 0
		
		// Store in Redis with TTL
		ttlDuration := time.Duration(entry.TTL) * time.Second
		err = sshMonitor.redisClient.Set(ctx, key, "allowed", ttlDuration).Err()
		if err != nil {
			log.Printf("Error storing SSH log rule in Redis: %v", err)
			continue
		}
		
		entry.ProcessedAsRule = true
		
		if os.Getenv("DEBUG") != "" {
			log.Printf("Stored SSH log rule in Redis: %s (TTL: %d seconds, new: %v)", key, entry.TTL, isNewRule)
		}
		
		// Execute script based on configuration (reuse existing script execution system)
		if invoke := os.Getenv("INVOKE_SCRIPT"); invoke != "" {
			ttlStr := strconv.Itoa(entry.TTL)
			executeScript(clientIP, ip, domain, ttlStr, "ALLOW", isNewRule)
		}
	}
	
	// Process extracted domains (if they're not already processed as part of IP rules)
	for _, domain := range entry.ExtractedDomains {
		if len(entry.ExtractedIPs) > 0 {
			continue // Already processed as part of IP rules
		}
		
		// For domain-only entries, we need to generate a placeholder IP or skip firewall integration
		// This depends on the specific use case - for now, we'll log but not create firewall rules
		log.Printf("Domain extracted from SSH log without associated IP: %s (from %s)", domain, entry.LogFile)
	}
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// sanitizeForDomain sanitizes a string for use in domain names
func sanitizeForDomain(input string) string {
	// Replace non-alphanumeric characters with hyphens
	reg := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	result := reg.ReplaceAllString(input, "-")
	
	// Remove leading/trailing hyphens
	result = strings.Trim(result, "-")
	
	// Limit length
	if len(result) > 50 {
		result = result[:50]
	}
	
	return strings.ToLower(result)
}

// getSSHLogMonitorStatus returns the status of SSH log monitoring
func getSSHLogMonitorStatus() *SSHMonitorStatus {
	sshMonitorMutex.RLock()
	defer sshMonitorMutex.RUnlock()
	
	status := &SSHMonitorStatus{
		Enabled:        sshLogConfig != nil && sshLogConfig.Enabled,
		ActiveServers:  0,
		TotalLogFiles:  0,
		ActiveLogFiles: 0,
		ServerStatuses: make(map[string]SSHServerStatus),
		LastUpdated:    time.Now(),
	}
	
	for name, monitor := range sshMonitors {
		monitor.mutex.RLock()
		serverStatus := *monitor.status
		monitor.mutex.RUnlock()
		
		status.ServerStatuses[name] = serverStatus
		
		if serverStatus.Connected {
			status.ActiveServers++
		}
		
		status.TotalLogFiles += len(monitor.config.LogFiles)
		status.ActiveLogFiles += serverStatus.LogFilesActive
	}
	
	return status
}

// stopSSHLogMonitoring stops all SSH log monitoring
func stopSSHLogMonitoring() {
	sshMonitorMutex.Lock()
	defer sshMonitorMutex.Unlock()
	
	for name, monitor := range sshMonitors {
		log.Printf("Stopping SSH log monitor: %s", name)
		monitor.cancel()
	}
	
	// Clear monitors
	sshMonitors = make(map[string]*SSHMonitor)
}