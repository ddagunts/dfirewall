package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	logCollectorConfig *LogCollectorConfig
	logCollectorStats  *LogCollectorStats
	logCollectorMutex  sync.RWMutex
	activeCollectors   map[string]*LogCollector
	collectorWaitGroup sync.WaitGroup
	collectorContext   context.Context
	collectorCancel    context.CancelFunc
)

// LogCollector represents an active log collection instance
type LogCollector struct {
	Source       *LogSource
	Stats        *SourceStats
	SSHClient    *ssh.Client
	SSHSession   *ssh.Session
	File         io.ReadCloser
	Scanner      *bufio.Scanner
	Watcher      *fsnotify.Watcher
	Context      context.Context
	Cancel       context.CancelFunc
	Mutex        sync.RWMutex
	LastPosition int64
}

// initializeLogCollector initializes the log collection system
func initializeLogCollector() error {
	logCollectorMutex.Lock()
	defer logCollectorMutex.Unlock()

	if logCollectorConfig == nil {
		return fmt.Errorf("log collector configuration not loaded")
	}

	if !logCollectorConfig.Enabled {
		log.Printf("Log collector disabled in configuration")
		return nil
	}

	// Initialize stats
	logCollectorStats = &LogCollectorStats{
		TotalSources:  len(logCollectorConfig.Sources),
		SourceStats:   make(map[string]*SourceStats),
		LastActivity: time.Now(),
	}

	// Initialize collectors map
	activeCollectors = make(map[string]*LogCollector)

	// Create context for managing all collectors
	collectorContext, collectorCancel = context.WithCancel(context.Background())

	// Validate and compile regex patterns
	for i, source := range logCollectorConfig.Sources {
		if err := validateLogSource(&source); err != nil {
			return fmt.Errorf("invalid log source %d (%s): %v", i, source.Name, err)
		}
	}

	log.Printf("Log collector initialized with %d sources", len(logCollectorConfig.Sources))
	return nil
}

// loadLogCollectorConfiguration loads log collector configuration from JSON file
func loadLogCollectorConfiguration(configPath string) (*LogCollectorConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log collector config file: %v", err)
	}

	var config LogCollectorConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse log collector JSON config: %v", err)
	}

	// Set defaults
	if config.BufferSize == 0 {
		config.BufferSize = 64 * 1024 // 64KB
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 60
	}
	if config.ReconnectDelay == 0 {
		config.ReconnectDelay = 10
	}
	if config.MaxReconnects == 0 {
		config.MaxReconnects = -1 // Unlimited
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 3600 // 1 hour
	}

	return &config, nil
}

// validateLogSource validates a log source configuration
func validateLogSource(source *LogSource) error {
	if source.Name == "" {
		return fmt.Errorf("source name is required")
	}

	if source.Type != "local" && source.Type != "ssh" {
		return fmt.Errorf("source type must be 'local' or 'ssh', got: %s", source.Type)
	}

	if source.FilePath == "" {
		return fmt.Errorf("file_path is required")
	}

	if source.Type == "ssh" {
		if source.Host == "" {
			return fmt.Errorf("host is required for SSH sources")
		}
		if source.Username == "" {
			return fmt.Errorf("username is required for SSH sources")
		}
		if source.Port == 0 {
			source.Port = 22
		}

		// Validate auth method
		switch source.AuthMethod {
		case "key":
			if source.PrivateKeyPath == "" && source.PrivateKeyData == "" {
				return fmt.Errorf("private_key_path or private_key_data required for key auth")
			}
		case "password":
			if source.Password == "" {
				return fmt.Errorf("password required for password auth")
			}
		case "key_password":
			if (source.PrivateKeyPath == "" && source.PrivateKeyData == "") || source.Password == "" {
				return fmt.Errorf("both private key and password required for key_password auth")
			}
		default:
			return fmt.Errorf("invalid auth_method: %s (must be 'key', 'password', or 'key_password')", source.AuthMethod)
		}

		// Validate SSH host key verification settings
		if err := validateSSHHostKeyConfig(source); err != nil {
			return fmt.Errorf("SSH host key configuration error: %v", err)
		}
	}

	// Validate patterns
	for i, pattern := range source.Patterns {
		if err := validateExtractionPattern(&pattern); err != nil {
			return fmt.Errorf("pattern %d (%s): %v", i, pattern.Name, err)
		}
	}

	return nil
}

// validateSSHHostKeyConfig validates SSH host key verification configuration
func validateSSHHostKeyConfig(source *LogSource) error {
	verification := source.HostKeyVerification
	if verification == "" {
		// Default to strict mode, which is secure
		return nil
	}

	switch verification {
	case "insecure":
		// Allow but warn - this will be logged during connection
		return nil

	case "known_hosts":
		// Validate known_hosts file path if specified
		if source.KnownHostsFile != "" {
			if _, err := os.Stat(source.KnownHostsFile); os.IsNotExist(err) {
				return fmt.Errorf("specified known_hosts file does not exist: %s", source.KnownHostsFile)
			}
		}
		return nil

	case "fingerprint":
		if source.HostKeyFingerprint == "" {
			return fmt.Errorf("host_key_fingerprint is required when using fingerprint verification")
		}

		fingerprint := source.HostKeyFingerprint
		// Remove SHA256: prefix if present
		if strings.HasPrefix(fingerprint, "SHA256:") {
			fingerprint = strings.TrimPrefix(fingerprint, "SHA256:")
		}

		// Validate that it's a valid base64 string (SHA256 fingerprints are 32 bytes = 44 base64 chars)
		// or valid hex string (64 hex chars)
		if len(fingerprint) != 44 && len(fingerprint) != 64 {
			return fmt.Errorf("invalid host_key_fingerprint format (expected SHA256 base64 or hex)")
		}

		// Try to decode as base64
		if len(fingerprint) == 44 {
			if _, err := base64.StdEncoding.DecodeString(fingerprint); err != nil {
				return fmt.Errorf("invalid host_key_fingerprint: not valid base64")
			}
		}

		// Try to decode as hex
		if len(fingerprint) == 64 {
			if _, err := hex.DecodeString(fingerprint); err != nil {
				return fmt.Errorf("invalid host_key_fingerprint: not valid hex")
			}
		}

		return nil

	case "strict":
		// Strict mode is always valid - it will try known_hosts first, then fingerprint if available
		return nil

	default:
		return fmt.Errorf("invalid host_key_verification method: %s (must be 'strict', 'known_hosts', 'fingerprint', or 'insecure')", verification)
	}
}

// validateExtractionPattern validates a regex extraction pattern
func validateExtractionPattern(pattern *ExtractionPattern) error {
	if pattern.Name == "" {
		return fmt.Errorf("pattern name is required")
	}

	if pattern.Regex == "" {
		return fmt.Errorf("regex is required")
	}

	if pattern.Type != "ip" && pattern.Type != "domain" && pattern.Type != "both" {
		return fmt.Errorf("pattern type must be 'ip', 'domain', or 'both', got: %s", pattern.Type)
	}

	// Compile regex to validate
	_, err := regexp.Compile(pattern.Regex)
	if err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}

	// Set default group numbers
	if pattern.IPGroup == 0 {
		pattern.IPGroup = 1
	}
	if pattern.DomainGroup == 0 {
		pattern.DomainGroup = 1
	}

	// Test pattern if test string is provided
	if pattern.TestString != "" {
		if err := testExtractionPattern(pattern); err != nil {
			return fmt.Errorf("pattern test failed: %v", err)
		}
	}

	return nil
}

// testExtractionPattern tests a pattern against its test string
func testExtractionPattern(pattern *ExtractionPattern) error {
	re, err := regexp.Compile(pattern.Regex)
	if err != nil {
		return err
	}

	matches := re.FindStringSubmatch(pattern.TestString)
	if matches == nil {
		return fmt.Errorf("pattern does not match test string")
	}

	// Validate group numbers
	if pattern.Type == "ip" || pattern.Type == "both" {
		if pattern.IPGroup >= len(matches) {
			return fmt.Errorf("IP group %d not found in matches (max: %d)", pattern.IPGroup, len(matches)-1)
		}
		ip := matches[pattern.IPGroup]
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("extracted IP '%s' is not valid", ip)
		}
	}

	if pattern.Type == "domain" || pattern.Type == "both" {
		if pattern.DomainGroup >= len(matches) {
			return fmt.Errorf("domain group %d not found in matches (max: %d)", pattern.DomainGroup, len(matches)-1)
		}
		domain := matches[pattern.DomainGroup]
		if domain == "" {
			return fmt.Errorf("extracted domain is empty")
		}
	}

	return nil
}

// startLogCollectors starts all configured log collectors
func startLogCollectors(redisClient *redis.Client) error {
	if logCollectorConfig == nil || !logCollectorConfig.Enabled {
		return nil
	}

	log.Printf("Starting %d log collectors", len(logCollectorConfig.Sources))

	for _, source := range logCollectorConfig.Sources {
		if !source.Enabled {
			log.Printf("Skipping disabled source: %s", source.Name)
			continue
		}

		collector, err := createLogCollector(&source, redisClient)
		if err != nil {
			log.Printf("Failed to create collector for source %s: %v", source.Name, err)
			continue
		}

		activeCollectors[source.Name] = collector

		// Start collector in background
		collectorWaitGroup.Add(1)
		go func(c *LogCollector) {
			defer collectorWaitGroup.Done()
			if err := c.Start(); err != nil {
				log.Printf("Collector %s failed: %v", c.Source.Name, err)
			}
		}(collector)

		log.Printf("Started log collector for %s (%s)", source.Name, source.Type)
	}

	// Start stats updater
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-collectorContext.Done():
				return
			case <-ticker.C:
				updateLogCollectorStats()
			}
		}
	}()

	return nil
}

// createLogCollector creates a new log collector instance
func createLogCollector(source *LogSource, redisClient *redis.Client) (*LogCollector, error) {
	ctx, cancel := context.WithCancel(collectorContext)

	stats := &SourceStats{
		Name:         source.Name,
		Status:       "disconnected",
		LastActivity: time.Now(),
	}

	logCollectorStats.SourceStats[source.Name] = stats

	collector := &LogCollector{
		Source:  source,
		Stats:   stats,
		Context: ctx,
		Cancel:  cancel,
	}

	return collector, nil
}

// Start starts the log collector
func (c *LogCollector) Start() error {
	defer c.cleanup()

	for {
		select {
		case <-c.Context.Done():
			return nil
		default:
		}

		if err := c.connect(); err != nil {
			c.updateStats("error", fmt.Sprintf("Connection failed: %v", err))
			
			if c.shouldReconnect() {
				time.Sleep(time.Duration(logCollectorConfig.ReconnectDelay) * time.Second)
				continue
			}
			return err
		}

		c.updateStats("connected", "")
		
		if err := c.tailFile(); err != nil {
			c.updateStats("error", fmt.Sprintf("Tailing failed: %v", err))
			c.disconnect()
			
			if c.shouldReconnect() {
				time.Sleep(time.Duration(logCollectorConfig.ReconnectDelay) * time.Second)
				continue
			}
			return err
		}
	}
}

// createHostKeyCallback creates the appropriate SSH host key verification callback
func (c *LogCollector) createHostKeyCallback() (ssh.HostKeyCallback, error) {
	verification := c.Source.HostKeyVerification
	if verification == "" {
		verification = "strict" // Default to strict verification
	}

	switch verification {
	case "insecure":
		log.Printf("WARNING: SSH host key verification disabled for %s - this is insecure!", c.Source.Name)
		return ssh.InsecureIgnoreHostKey(), nil

	case "known_hosts":
		knownHostsFile := c.Source.KnownHostsFile
		if knownHostsFile == "" {
			// Use default known_hosts file
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %v", err)
			}
			knownHostsFile = filepath.Join(homeDir, ".ssh", "known_hosts")
		}

		// Check if known_hosts file exists
		if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("known_hosts file not found: %s", knownHostsFile)
		}

		callback, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %s: %v", knownHostsFile, err)
		}
		
		log.Printf("Using known_hosts file for SSH host key verification: %s", knownHostsFile)
		return callback, nil

	case "fingerprint":
		if c.Source.HostKeyFingerprint == "" {
			return nil, fmt.Errorf("host_key_fingerprint is required when using fingerprint verification")
		}

		expectedFingerprint := c.Source.HostKeyFingerprint
		// Remove common prefixes if present
		if strings.HasPrefix(expectedFingerprint, "SHA256:") {
			expectedFingerprint = strings.TrimPrefix(expectedFingerprint, "SHA256:")
		}

		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Calculate SHA256 fingerprint
			hash := sha256.Sum256(key.Marshal())
			fingerprint := base64.StdEncoding.EncodeToString(hash[:])
			
			if fingerprint != expectedFingerprint {
				// Also try hex encoding for compatibility
				hexFingerprint := hex.EncodeToString(hash[:])
				if hexFingerprint != expectedFingerprint {
					return fmt.Errorf("SSH host key fingerprint mismatch for %s: expected %s, got SHA256:%s", 
						hostname, expectedFingerprint, fingerprint)
				}
			}
			
			log.Printf("SSH host key fingerprint verified for %s: SHA256:%s", hostname, fingerprint)
			return nil
		}, nil

	case "strict":
		// Strict verification - try known_hosts first, fall back to fingerprint if provided
		homeDir, err := os.UserHomeDir()
		if err == nil {
			knownHostsFile := filepath.Join(homeDir, ".ssh", "known_hosts")
			if _, err := os.Stat(knownHostsFile); err == nil {
				callback, err := knownhosts.New(knownHostsFile)
				if err == nil {
					log.Printf("Using system known_hosts file for strict SSH host key verification: %s", knownHostsFile)
					return callback, nil
				}
			}
		}

		// If known_hosts is not available but fingerprint is provided, use fingerprint verification
		if c.Source.HostKeyFingerprint != "" {
			log.Printf("Using fingerprint verification as fallback for strict mode")
			// Temporarily set verification mode to fingerprint and call the function
			origVerification := c.Source.HostKeyVerification
			c.Source.HostKeyVerification = "fingerprint"
			callback, err := c.createHostKeyCallback()
			c.Source.HostKeyVerification = origVerification // Restore original value
			return callback, err
		}

		return nil, fmt.Errorf("strict host key verification requires either a known_hosts file or host_key_fingerprint to be configured")

	default:
		return nil, fmt.Errorf("invalid host_key_verification method: %s (must be 'strict', 'known_hosts', 'fingerprint', or 'insecure')", verification)
	}
}

// connect establishes connection to log source
func (c *LogCollector) connect() error {
	if c.Source.Type == "ssh" {
		return c.connectSSH()
	}
	return c.connectLocal()
}

// connectSSH establishes SSH connection
func (c *LogCollector) connectSSH() error {
	// Create host key verification callback
	hostKeyCallback, err := c.createHostKeyCallback()
	if err != nil {
		return fmt.Errorf("failed to setup SSH host key verification: %v", err)
	}

	config := &ssh.ClientConfig{
		User:            c.Source.Username,
		Timeout:         time.Duration(logCollectorConfig.ConnectTimeout) * time.Second,
		HostKeyCallback: hostKeyCallback,
	}

	// Set up authentication
	switch c.Source.AuthMethod {
	case "password", "key_password":
		config.Auth = append(config.Auth, ssh.Password(c.Source.Password))
	}

	if c.Source.AuthMethod == "key" || c.Source.AuthMethod == "key_password" {
		var keyData []byte
		var err error

		if c.Source.PrivateKeyData != "" {
			keyData, err = base64.StdEncoding.DecodeString(c.Source.PrivateKeyData)
			if err != nil {
				return fmt.Errorf("failed to decode private key data: %v", err)
			}
		} else {
			keyData, err = os.ReadFile(c.Source.PrivateKeyPath)
			if err != nil {
				return fmt.Errorf("failed to read private key file: %v", err)
			}
		}

		var signer ssh.Signer
		if c.Source.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(c.Source.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", c.Source.Host, c.Source.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH connection failed: %v", err)
	}

	c.SSHClient = client
	return nil
}

// connectLocal prepares local file access
func (c *LogCollector) connectLocal() error {
	// Check if file exists
	if _, err := os.Stat(c.Source.FilePath); err != nil {
		return fmt.Errorf("local file not accessible: %v", err)
	}

	// Set up file system watcher for rotation detection
	if c.Source.FollowRotation {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create file watcher: %v", err)
		}
		
		dir := filepath.Dir(c.Source.FilePath)
		if err := watcher.Add(dir); err != nil {
			watcher.Close()
			return fmt.Errorf("failed to watch directory: %v", err)
		}
		
		c.Watcher = watcher
	}

	return nil
}

// tailFile starts tailing the log file
func (c *LogCollector) tailFile() error {
	var reader io.ReadCloser
	var err error

	if c.Source.Type == "ssh" {
		reader, err = c.openSSHFile()
	} else {
		reader, err = c.openLocalFile()
	}

	if err != nil {
		return err
	}

	c.File = reader
	c.Scanner = bufio.NewScanner(reader)

	// Set buffer size
	buf := make([]byte, 0, logCollectorConfig.BufferSize)
	c.Scanner.Buffer(buf, logCollectorConfig.BufferSize)

	return c.processLines()
}

// openSSHFile opens remote file via SSH
func (c *LogCollector) openSSHFile() (io.ReadCloser, error) {
	session, err := c.SSHClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %v", err)
	}

	c.SSHSession = session

	// Use tail command to follow file
	var cmd string
	if c.Source.StartFromEnd {
		cmd = fmt.Sprintf("tail -F %s", c.Source.FilePath)
	} else {
		cmd = fmt.Sprintf("tail -F -n +1 %s", c.Source.FilePath)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := session.Start(cmd); err != nil {
		return nil, fmt.Errorf("failed to start tail command: %v", err)
	}

	// Wrap stdout in a ReadCloser that also closes the session
	return &sshReadCloser{reader: stdout, session: session}, nil
}

// sshReadCloser wraps an io.Reader and ssh.Session to provide ReadCloser interface
type sshReadCloser struct {
	reader  io.Reader
	session *ssh.Session
}

func (src *sshReadCloser) Read(p []byte) (n int, err error) {
	return src.reader.Read(p)
}

func (src *sshReadCloser) Close() error {
	if src.session != nil {
		return src.session.Close()
	}
	return nil
}

// openLocalFile opens local file
func (c *LogCollector) openLocalFile() (io.ReadCloser, error) {
	file, err := os.Open(c.Source.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open local file: %v", err)
	}

	// Seek to end if configured
	if c.Source.StartFromEnd {
		if _, err := file.Seek(0, io.SeekEnd); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to seek to end: %v", err)
		}
	}

	return file, nil
}

// processLines processes incoming log lines
func (c *LogCollector) processLines() error {
	redisClient, err := createRedisClient(os.Getenv("REDIS"))
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %v", err)
	}

	for {
		select {
		case <-c.Context.Done():
			return nil
		default:
		}

		// Set read timeout
		if c.Source.Type == "local" {
			if f, ok := c.File.(*os.File); ok {
				f.SetReadDeadline(time.Now().Add(time.Duration(logCollectorConfig.ReadTimeout) * time.Second))
			}
		}

		if !c.Scanner.Scan() {
			if err := c.Scanner.Err(); err != nil {
				return fmt.Errorf("scanner error: %v", err)
			}
			// EOF reached, continue if following file
			if c.Source.Type == "ssh" || c.Source.FollowRotation {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil
		}

		line := c.Scanner.Text()
		if line == "" {
			continue
		}

		c.Mutex.Lock()
		c.Stats.LinesRead++
		c.Stats.LastLine = line
		c.Stats.LastActivity = time.Now()
		c.Mutex.Unlock()

		// Process line through extraction patterns
		if err := c.processLine(line, redisClient); err != nil {
			log.Printf("Error processing line from %s: %v", c.Source.Name, err)
		}
	}
}

// processLine processes a single log line
func (c *LogCollector) processLine(line string, redisClient *redis.Client) error {
	for _, pattern := range c.Source.Patterns {
		if !pattern.Enabled {
			continue
		}

		re, err := regexp.Compile(pattern.Regex)
		if err != nil {
			continue // Skip invalid patterns
		}

		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		entry := &LogEntry{
			Source:        c.Source.Name,
			OriginalLine:  line,
			Timestamp:     time.Now(),
			PatternMatched: pattern.Name,
			ProcessedAt:   time.Now(),
		}

		// Extract IPs
		if pattern.Type == "ip" || pattern.Type == "both" {
			if pattern.IPGroup < len(matches) {
				ip := strings.TrimSpace(matches[pattern.IPGroup])
				if net.ParseIP(ip) != nil {
					entry.ExtractedIPs = append(entry.ExtractedIPs, ip)
					c.Mutex.Lock()
					c.Stats.IPsExtracted++
					c.Mutex.Unlock()
				}
			}
		}

		// Extract domains
		if pattern.Type == "domain" || pattern.Type == "both" {
			if pattern.DomainGroup < len(matches) {
				domain := strings.TrimSpace(matches[pattern.DomainGroup])
				if domain != "" && isValidDomain(domain) {
					entry.ExtractedDomains = append(entry.ExtractedDomains, domain)
					c.Mutex.Lock()
					c.Stats.DomainsExtracted++
					c.Mutex.Unlock()
				}
			}
		}

		// Extract client IP if configured
		if pattern.ClientIPGroup > 0 && pattern.ClientIPGroup < len(matches) {
			clientIP := strings.TrimSpace(matches[pattern.ClientIPGroup])
			if net.ParseIP(clientIP) != nil {
				entry.ClientIP = clientIP
			}
		}

		// Process extracted data
		if len(entry.ExtractedIPs) > 0 || len(entry.ExtractedDomains) > 0 {
			if err := c.processExtractedData(entry, redisClient); err != nil {
				return err
			}
		}

		// Only process first matching pattern
		break
	}

	return nil
}

// processExtractedData processes extracted IPs and domains
func (c *LogCollector) processExtractedData(entry *LogEntry, redisClient *redis.Client) error {
	ctx := context.Background()
	ttl := c.Source.TTL
	if ttl == 0 {
		ttl = logCollectorConfig.DefaultTTL
	}

	// Use extracted client IP or fallback to "127.0.0.1" for log-based entries
	clientIP := entry.ClientIP
	if clientIP == "" {
		clientIP = "127.0.0.1" // Default for log entries without client info
	}

	// Process extracted IPs
	for _, ip := range entry.ExtractedIPs {
		// Store in Redis with TTL
		key := fmt.Sprintf("rules:%s|%s|log:%s", clientIP, ip, entry.Source)
		
		ttlDuration := time.Duration(ttl) * time.Second
		err := redisClient.Set(ctx, key, "allowed", ttlDuration).Err()
		if err != nil {
			log.Printf("Error storing log-extracted IP rule in Redis: %v", err)
			continue
		}

		if os.Getenv("DEBUG") != "" {
			log.Printf("Stored log-extracted IP rule: %s (TTL: %d seconds)", key, ttl)
		}

		// Execute script if configured
		domain := fmt.Sprintf("log:%s", entry.Source)
		ttlStr := strconv.Itoa(ttl)
		executeScript(clientIP, ip, domain, ttlStr, "ALLOW", true)
	}

	// Process extracted domains
	for _, domain := range entry.ExtractedDomains {
		// For domains, we create a placeholder rule since we don't have the resolved IP
		key := fmt.Sprintf("rules:%s|0.0.0.0|%s", clientIP, domain)
		
		ttlDuration := time.Duration(ttl) * time.Second
		err := redisClient.Set(ctx, key, "allowed", ttlDuration).Err()
		if err != nil {
			log.Printf("Error storing log-extracted domain rule in Redis: %v", err)
			continue
		}

		if os.Getenv("DEBUG") != "" {
			log.Printf("Stored log-extracted domain rule: %s (TTL: %d seconds)", key, ttl)
		}

		// Execute script if configured
		ttlStr := strconv.Itoa(ttl)
		executeScript(clientIP, "0.0.0.0", domain, ttlStr, "ALLOW", true)
	}

	return nil
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")
	
	// Check for valid characters and structure
	for _, part := range strings.Split(domain, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
				 (char >= '0' && char <= '9') || char == '-') {
				return false
			}
		}
	}
	
	return true
}

// shouldReconnect determines if collector should attempt reconnection
func (c *LogCollector) shouldReconnect() bool {
	if logCollectorConfig.MaxReconnects == -1 {
		return true
	}
	
	c.Mutex.RLock()
	defer c.Mutex.RUnlock()
	
	return c.Stats.ReconnectCount < logCollectorConfig.MaxReconnects
}

// disconnect closes connections
func (c *LogCollector) disconnect() {
	if c.File != nil {
		c.File.Close()
		c.File = nil
	}
	
	if c.SSHSession != nil {
		c.SSHSession.Close()
		c.SSHSession = nil
	}
	
	if c.SSHClient != nil {
		c.SSHClient.Close()
		c.SSHClient = nil
	}
	
	if c.Watcher != nil {
		c.Watcher.Close()
		c.Watcher = nil
	}
}

// cleanup performs final cleanup
func (c *LogCollector) cleanup() {
	c.disconnect()
	c.updateStats("disconnected", "")
}

// updateStats updates collector statistics
func (c *LogCollector) updateStats(status, errorMsg string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	
	c.Stats.Status = status
	c.Stats.LastActivity = time.Now()
	
	if errorMsg != "" {
		c.Stats.LastError = errorMsg
		c.Stats.ErrorCount++
	}
	
	if status == "connected" {
		c.Stats.ConnectedAt = time.Now()
	} else if status == "error" {
		c.Stats.ReconnectCount++
	}
}

// updateLogCollectorStats updates global statistics
func updateLogCollectorStats() {
	logCollectorMutex.Lock()
	defer logCollectorMutex.Unlock()
	
	if logCollectorStats == nil {
		return
	}
	
	activeCount := 0
	totalLines := int64(0)
	totalIPs := int64(0)
	totalDomains := int64(0)
	totalErrors := int64(0)
	
	for _, stats := range logCollectorStats.SourceStats {
		if stats.Status == "connected" {
			activeCount++
		}
		totalLines += stats.LinesRead
		totalIPs += stats.IPsExtracted
		totalDomains += stats.DomainsExtracted
		totalErrors += stats.ErrorCount
	}
	
	logCollectorStats.ActiveSources = activeCount
	logCollectorStats.TotalLinesRead = totalLines
	logCollectorStats.IPsExtracted = totalIPs
	logCollectorStats.DomainsExtracted = totalDomains
	logCollectorStats.ErrorCount = totalErrors
	logCollectorStats.LastActivity = time.Now()
}

// stopLogCollectors stops all log collectors
func stopLogCollectors() {
	if collectorCancel != nil {
		collectorCancel()
	}
	
	// Wait for all collectors to stop
	collectorWaitGroup.Wait()
	
	log.Printf("All log collectors stopped")
}

// getLogCollectorStats returns current statistics
func getLogCollectorStats() *LogCollectorStats {
	logCollectorMutex.RLock()
	defer logCollectorMutex.RUnlock()
	
	if logCollectorStats == nil {
		return &LogCollectorStats{}
	}
	
	// Update stats before returning
	updateLogCollectorStats()
	
	// Return a copy
	statsCopy := *logCollectorStats
	return &statsCopy
}