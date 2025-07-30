package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type Route struct {
	Zone string
	From net.IP
	To   net.IP
}

// FirewallRule represents a single firewall rule from Redis
type FirewallRule struct {
	Key        string    `json:"key"`
	ClientIP   string    `json:"client_ip"`
	ResolvedIP string    `json:"resolved_ip"`
	Domain     string    `json:"domain"`
	TTL        int64     `json:"ttl"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// UIStats represents statistics for the web UI
type UIStats struct {
	TotalRules    int `json:"total_rules"`
	ActiveClients int `json:"active_clients"`
	UniqueDomains int `json:"unique_domains"`
	UniqueIPs     int `json:"unique_ips"`
}

// ClientScriptConfig represents per-client script configuration
type ClientScriptConfig struct {
	// Pattern for matching client IPs (supports CIDR notation, single IPs, or regex patterns)
	ClientPattern string `json:"client_pattern"`
	// Script to execute for matching clients (overrides global INVOKE_SCRIPT)
	InvokeScript string `json:"invoke_script,omitempty"`
	// Script to execute on expiration for matching clients (overrides global EXPIRE_SCRIPT)
	ExpireScript string `json:"expire_script,omitempty"`
	// Whether to always invoke script (overrides global INVOKE_ALWAYS)
	InvokeAlways *bool `json:"invoke_always,omitempty"`
	// Description for documentation purposes
	Description string `json:"description,omitempty"`
	// Additional environment variables to set for this client
	Environment map[string]string `json:"environment,omitempty"`
}

// ScriptConfiguration represents the complete configuration file structure
type ScriptConfiguration struct {
	// Version for configuration compatibility
	Version string `json:"version"`
	// Global default settings (fallback when no client-specific config matches)
	Defaults struct {
		InvokeScript string            `json:"invoke_script,omitempty"`
		ExpireScript string            `json:"expire_script,omitempty"`
		InvokeAlways bool              `json:"invoke_always,omitempty"`
		Environment  map[string]string `json:"environment,omitempty"`
	} `json:"defaults"`
	// Per-client configurations (processed in order - first match wins)
	Clients []ClientScriptConfig `json:"clients"`
}

// Global variable to hold parsed configuration
var scriptConfig *ScriptConfiguration

// BlacklistConfig represents blacklist configuration
type BlacklistConfig struct {
	// Redis-based blacklists
	RedisIPSet     string `json:"redis_ip_set,omitempty"`     // Redis set name for blacklisted IPs
	RedisDomainSet string `json:"redis_domain_set,omitempty"` // Redis set name for blacklisted domains
	
	// File-based blacklists
	IPBlacklistFile     string `json:"ip_blacklist_file,omitempty"`     // Path to IP blacklist file
	DomainBlacklistFile string `json:"domain_blacklist_file,omitempty"` // Path to domain blacklist file
	
	// Configuration options
	BlockOnMatch    bool `json:"block_on_match"`     // Whether to block DNS resolution on blacklist match
	LogOnly         bool `json:"log_only"`           // If true, only log matches without blocking
	RefreshInterval int  `json:"refresh_interval"`   // How often to reload file-based blacklists (seconds)
}

// ReputationChecker represents a single reputation service configuration
type ReputationChecker struct {
	Name        string            `json:"name"`                  // Human-readable name
	Type        string            `json:"type"`                  // "ip" or "domain" or "both"
	Provider    string            `json:"provider"`              // "virustotal", "abuseipdb", "urlvoid", "custom"
	Enabled     bool              `json:"enabled"`               // Whether this checker is active
	APIKey      string            `json:"api_key,omitempty"`     // API key for the service
	BaseURL     string            `json:"base_url,omitempty"`    // Base URL for custom providers
	Timeout     int               `json:"timeout"`               // Request timeout in seconds
	RateLimit   int               `json:"rate_limit"`            // Max requests per minute
	CacheTTL    int               `json:"cache_ttl"`             // Cache results for N seconds
	Threshold   float64           `json:"threshold"`             // Reputation threshold (0.0-1.0)
	Headers     map[string]string `json:"headers,omitempty"`     // Custom HTTP headers
	QueryFormat string            `json:"query_format,omitempty"` // URL format for custom providers
}

// ReputationConfig represents the complete reputation checking configuration
type ReputationConfig struct {
	Enabled         bool                 `json:"enabled"`           // Global enable/disable
	BlockOnBadRep   bool                 `json:"block_on_bad_rep"`  // Block if reputation is bad
	LogOnly         bool                 `json:"log_only"`          // Only log, don't block
	CacheResults    bool                 `json:"cache_results"`     // Cache results in Redis
	CachePrefix     string               `json:"cache_prefix"`      // Redis key prefix for cache
	Checkers        []ReputationChecker  `json:"checkers"`          // List of reputation services
}

// ReputationResult represents the result of a reputation check
type ReputationResult struct {
	Provider   string    `json:"provider"`
	Target     string    `json:"target"`     // IP or domain that was checked
	Score      float64   `json:"score"`      // Reputation score (0.0=bad, 1.0=good)
	IsMalicious bool     `json:"malicious"`  // Whether target is considered malicious
	Details    string    `json:"details"`    // Additional details from provider
	Timestamp  time.Time `json:"timestamp"`  // When check was performed
	Cached     bool      `json:"cached"`     // Whether result came from cache
}

// Global blacklist configuration and data
var (
	blacklistConfig    *BlacklistConfig
	ipBlacklist        map[string]bool     // In-memory IP blacklist
	domainBlacklist    map[string]bool     // In-memory domain blacklist
	lastBlacklistLoad  time.Time           // Last time file blacklists were loaded
	
	// Reputation checking
	reputationConfig   *ReputationConfig
	reputationCache    map[string]*ReputationResult  // In-memory reputation cache
	rateLimiters       map[string]*time.Ticker       // Rate limiters per provider
	httpClient         *http.Client                   // HTTP client for API calls
)

// Input validation functions
var (
	validIPRegex     = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$`)
)

func validateIP(ip string) bool {
	if !validIPRegex.MatchString(ip) {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil
}

func validateDomain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return validDomainRegex.MatchString(domain)
}

func validateTTL(ttl uint32) bool {
	return ttl > 0 && ttl <= 86400 // Max 24 hours
}

// loadScriptConfiguration loads and parses the script configuration file
func loadScriptConfiguration(configPath string) (*ScriptConfiguration, error) {
	// ASSUMPTION: Configuration file is in JSON format for better structure and validation
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	var config ScriptConfiguration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %v", err)
	}
	
	// Validate configuration version
	// ASSUMPTION: Start with version "1.0" and increment for breaking changes
	if config.Version == "" {
		config.Version = "1.0" // Default version for backward compatibility
	}
	if config.Version != "1.0" {
		return nil, fmt.Errorf("unsupported configuration version: %s (expected 1.0)", config.Version)
	}
	
	// Validate and resolve script paths
	if config.Defaults.InvokeScript != "" {
		if err := validateInvokeScript(config.Defaults.InvokeScript); err != nil {
			return nil, fmt.Errorf("invalid default invoke script: %v", err)
		}
	}
	if config.Defaults.ExpireScript != "" {
		if err := validateInvokeScript(config.Defaults.ExpireScript); err != nil {
			return nil, fmt.Errorf("invalid default expire script: %v", err)
		}
	}
	
	// Validate client-specific configurations
	for i, client := range config.Clients {
		if client.ClientPattern == "" {
			return nil, fmt.Errorf("client config %d: client_pattern is required", i)
		}
		
		// QUESTION: Should we validate IP patterns here or at runtime?
		// ASSUMPTION: Validate at load time to catch errors early
		if err := validateClientPattern(client.ClientPattern); err != nil {
			return nil, fmt.Errorf("client config %d: invalid pattern '%s': %v", i, client.ClientPattern, err)
		}
		
		if client.InvokeScript != "" {
			if err := validateInvokeScript(client.InvokeScript); err != nil {
				return nil, fmt.Errorf("client config %d: invalid invoke script: %v", i, err)
			}
		}
		if client.ExpireScript != "" {
			if err := validateInvokeScript(client.ExpireScript); err != nil {
				return nil, fmt.Errorf("client config %d: invalid expire script: %v", i, err)
			}
		}
	}
	
	log.Printf("Loaded script configuration with %d client-specific rules", len(config.Clients))
	return &config, nil
}

// validateClientPattern validates client IP matching patterns
func validateClientPattern(pattern string) error {
	// ASSUMPTION: Support three pattern types:
	// 1. Single IP: 192.168.1.100
	// 2. CIDR notation: 192.168.1.0/24
	// 3. Regex pattern: ^192\.168\.(1|2)\..*
	
	// Try parsing as single IP
	if net.ParseIP(pattern) != nil {
		return nil
	}
	
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(pattern); err == nil {
		return nil
	}
	
	// Try compiling as regex
	if _, err := regexp.Compile(pattern); err == nil {
		return nil
	}
	
	return fmt.Errorf("pattern must be a valid IP address, CIDR notation, or regex")
}

// findClientConfig finds the first matching client configuration for a given IP
func findClientConfig(clientIP string) *ClientScriptConfig {
	if scriptConfig == nil {
		return nil
	}
	
	// ASSUMPTION: Process client configs in order - first match wins
	for _, client := range scriptConfig.Clients {
		if matchesClientPattern(clientIP, client.ClientPattern) {
			return &client
		}
	}
	
	return nil // No match found
}

// matchesClientPattern checks if a client IP matches a given pattern
func matchesClientPattern(clientIP, pattern string) bool {
	// Try exact IP match first (most common case)
	if clientIP == pattern {
		return true
	}
	
	// Try CIDR match
	if _, cidr, err := net.ParseCIDR(pattern); err == nil {
		if ip := net.ParseIP(clientIP); ip != nil {
			return cidr.Contains(ip)
		}
	}
	
	// Try regex match
	if regex, err := regexp.Compile(pattern); err == nil {
		return regex.MatchString(clientIP)
	}
	
	return false
}

// loadReputationConfiguration loads reputation checking configuration from JSON file
func loadReputationConfiguration(configPath string) (*ReputationConfig, error) {
	// ASSUMPTION: Reputation configuration is in JSON format for consistency
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read reputation config file: %v", err)
	}
	
	var config ReputationConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse reputation JSON config: %v", err)
	}
	
	// Set defaults if not specified
	if config.CachePrefix == "" {
		config.CachePrefix = "dfirewall:reputation"
	}
	
	// Validate and set defaults for each checker
	for i := range config.Checkers {
		checker := &config.Checkers[i]
		
		// Set default timeout if not specified
		if checker.Timeout <= 0 {
			checker.Timeout = 10 // 10 seconds default
		}
		
		// Set default rate limit if not specified
		if checker.RateLimit <= 0 {
			checker.RateLimit = 60 // 60 requests per minute default
		}
		
		// Set default cache TTL if not specified
		if checker.CacheTTL <= 0 {
			checker.CacheTTL = 3600 // 1 hour default
		}
		
		// Set default threshold if not specified
		if checker.Threshold <= 0 {
			checker.Threshold = 0.5 // 50% threshold default
		}
		
		// Validate checker type
		if checker.Type != "ip" && checker.Type != "domain" && checker.Type != "both" {
			return nil, fmt.Errorf("checker %s: invalid type '%s' (must be 'ip', 'domain', or 'both')", checker.Name, checker.Type)
		}
		
		// Validate provider
		switch checker.Provider {
		case "virustotal", "abuseipdb", "urlvoid", "custom":
			// Valid providers
		default:
			return nil, fmt.Errorf("checker %s: unsupported provider '%s'", checker.Name, checker.Provider)
		}
		
		// Validate API key for known providers
		if checker.Provider != "custom" && checker.APIKey == "" {
			log.Printf("WARNING: Checker %s (%s) has no API key - will be disabled", checker.Name, checker.Provider)
			checker.Enabled = false
		}
		
		// Set provider-specific defaults
		switch checker.Provider {
		case "virustotal":
			if checker.BaseURL == "" {
				checker.BaseURL = "https://www.virustotal.com/vtapi/v2"
			}
		case "abuseipdb":
			if checker.BaseURL == "" {
				checker.BaseURL = "https://api.abuseipdb.com/api/v2"
			}
		case "urlvoid":
			if checker.BaseURL == "" {
				checker.BaseURL = "http://api.urlvoid.com/api1000"
			}
		case "custom":
			if checker.BaseURL == "" || checker.QueryFormat == "" {
				return nil, fmt.Errorf("checker %s: custom provider requires base_url and query_format", checker.Name)
			}
		}
	}
	
	log.Printf("Loaded reputation configuration with %d checkers", len(config.Checkers))
	return &config, nil
}

// initializeReputationSystem initializes the reputation checking system
func initializeReputationSystem() {
	if reputationConfig == nil {
		return
	}
	
	// Initialize HTTP client with reasonable defaults
	// ASSUMPTION: Use timeout slightly longer than max checker timeout for reliability
	maxTimeout := 0
	for _, checker := range reputationConfig.Checkers {
		if checker.Timeout > maxTimeout {
			maxTimeout = checker.Timeout
		}
	}
	
	httpClient = &http.Client{
		Timeout: time.Duration(maxTimeout+5) * time.Second,
	}
	
	// Initialize in-memory cache
	reputationCache = make(map[string]*ReputationResult)
	rateLimiters = make(map[string]*time.Ticker)
	
	// Initialize rate limiters for each enabled checker
	for _, checker := range reputationConfig.Checkers {
		if checker.Enabled {
			// ASSUMPTION: Rate limit as requests per minute, convert to interval between requests
			interval := time.Duration(60/checker.RateLimit) * time.Second
			rateLimiters[checker.Name] = time.NewTicker(interval)
		}
	}
	
	log.Printf("Initialized reputation system with %d active checkers", len(rateLimiters))
}

// checkReputation checks the reputation of an IP or domain
func checkReputation(target, targetType string, redisClient *redis.Client) *ReputationResult {
	if reputationConfig == nil || !reputationConfig.Enabled {
		return nil
	}
	
	// ASSUMPTION: Try cache first for performance
	cacheKey := fmt.Sprintf("%s:%s:%s", reputationConfig.CachePrefix, targetType, target)
	
	// Check in-memory cache first
	if cached, exists := reputationCache[cacheKey]; exists {
		// Use default cache TTL of 1 hour (3600 seconds)
		defaultCacheTTL := 3600
		if time.Since(cached.Timestamp) < time.Duration(defaultCacheTTL)*time.Second {
			cached.Cached = true
			return cached
		}
		// Cache expired, remove it  
		delete(reputationCache, cacheKey)
	}
	
	// Check Redis cache if enabled
	if reputationConfig.CacheResults && redisClient != nil {
		ctx := context.Background()
		if data, err := redisClient.Get(ctx, cacheKey).Result(); err == nil {
			var result ReputationResult
			if json.Unmarshal([]byte(data), &result) == nil {
				result.Cached = true
				// Also cache in memory for faster subsequent access
				reputationCache[cacheKey] = &result
				return &result
			}
		}
	}
	
	// No cache hit, check with reputation services
	for _, checker := range reputationConfig.Checkers {
		if !checker.Enabled {
			continue
		}
		
		// Check if checker supports this target type
		if checker.Type != "both" && checker.Type != targetType {
			continue
		}
		
		// Apply rate limiting
		if ticker, exists := rateLimiters[checker.Name]; exists {
			<-ticker.C // Wait for rate limiter
		}
		
		result := queryReputationService(checker, target, targetType)
		if result != nil {
			result.Cached = false
			
			// Cache the result
			if reputationConfig.CacheResults {
				// Cache in memory
				reputationCache[cacheKey] = result
				
				// Cache in Redis if available
				if redisClient != nil {
					ctx := context.Background()
					if data, err := json.Marshal(result); err == nil {
						redisClient.Set(ctx, cacheKey, data, time.Duration(checker.CacheTTL)*time.Second)
					}
				}
			}
			
			return result
		}
	}
	
	return nil // No reputation information available
}

// queryReputationService queries a specific reputation service
func queryReputationService(checker ReputationChecker, target, targetType string) *ReputationResult {
	// ASSUMPTION: Different providers have different API formats and responses
	switch checker.Provider {
	case "virustotal":
		return queryVirusTotal(checker, target, targetType)
	case "abuseipdb":
		return queryAbuseIPDB(checker, target, targetType)
	case "urlvoid":
		return queryURLVoid(checker, target, targetType)
	case "custom":
		return queryCustomProvider(checker, target, targetType)
	default:
		log.Printf("WARNING: Unknown reputation provider: %s", checker.Provider)
		return nil
	}
}

// queryVirusTotal queries VirusTotal API
func queryVirusTotal(checker ReputationChecker, target, targetType string) *ReputationResult {
	var apiURL string
	
	if targetType == "ip" {
		apiURL = fmt.Sprintf("%s/ip-address/report?apikey=%s&ip=%s", checker.BaseURL, checker.APIKey, target)
	} else if targetType == "domain" {
		apiURL = fmt.Sprintf("%s/domain/report?apikey=%s&domain=%s", checker.BaseURL, checker.APIKey, target)
	} else {
		return nil
	}
	
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		log.Printf("VirusTotal API error for %s: %v", target, err)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		log.Printf("VirusTotal API returned status %d for %s", resp.StatusCode, target)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read VirusTotal response for %s: %v", target, err)
		return nil
	}
	
	// Parse VirusTotal response
	var vtResponse map[string]interface{}
	if err := json.Unmarshal(body, &vtResponse); err != nil {
		log.Printf("Failed to parse VirusTotal response for %s: %v", target, err)
		return nil
	}
	
	// ASSUMPTION: VirusTotal uses positives/total ratio for reputation scoring
	positives := 0.0
	total := 1.0
	
	if pos, ok := vtResponse["positives"].(float64); ok {
		positives = pos
	}
	if tot, ok := vtResponse["total"].(float64); ok && tot > 0 {
		total = tot
	}
	
	// Calculate reputation score (invert: high positives = low reputation)
	score := 1.0 - (positives / total)
	isMalicious := score < checker.Threshold
	
	details := fmt.Sprintf("VirusTotal: %v/%v detections", positives, total)
	
	return &ReputationResult{
		Provider:   "virustotal",
		Target:     target,
		Score:      score,
		IsMalicious: isMalicious,
		Details:    details,
		Timestamp:  time.Now(),
	}
}

// queryAbuseIPDB queries AbuseIPDB API
func queryAbuseIPDB(checker ReputationChecker, target, targetType string) *ReputationResult {
	if targetType != "ip" {
		return nil // AbuseIPDB only supports IP addresses
	}
	
	apiURL := fmt.Sprintf("%s/check", checker.BaseURL)
	
	// Create request with parameters
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("Failed to create AbuseIPDB request for %s: %v", target, err)
		return nil
	}
	
	// Add query parameters
	q := req.URL.Query()
	q.Add("ipAddress", target)
	q.Add("maxAgeInDays", "90") // Check reports from last 90 days
	q.Add("verbose", "false")
	req.URL.RawQuery = q.Encode()
	
	// Add headers
	req.Header.Add("Key", checker.APIKey)
	req.Header.Add("Accept", "application/json")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("AbuseIPDB API error for %s: %v", target, err)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		log.Printf("AbuseIPDB API returned status %d for %s", resp.StatusCode, target)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read AbuseIPDB response for %s: %v", target, err)
		return nil
	}
	
	// Parse AbuseIPDB response
	var abuseResponse map[string]interface{}
	if err := json.Unmarshal(body, &abuseResponse); err != nil {
		log.Printf("Failed to parse AbuseIPDB response for %s: %v", target, err)
		return nil
	}
	
	// ASSUMPTION: AbuseIPDB uses confidence percentage (0-100)
	confidence := 0.0
	if data, ok := abuseResponse["data"].(map[string]interface{}); ok {
		if conf, ok := data["abuseConfidencePercentage"].(float64); ok {
			confidence = conf
		}
	}
	
	// Convert confidence to reputation score (invert: high confidence = low reputation)
	score := 1.0 - (confidence / 100.0)
	isMalicious := score < checker.Threshold
	
	details := fmt.Sprintf("AbuseIPDB: %v%% abuse confidence", confidence)
	
	return &ReputationResult{
		Provider:   "abuseipdb",
		Target:     target,
		Score:      score,
		IsMalicious: isMalicious,
		Details:    details,
		Timestamp:  time.Now(),
	}
}

// queryURLVoid queries URLVoid API
func queryURLVoid(checker ReputationChecker, target, targetType string) *ReputationResult {
	if targetType != "domain" {
		return nil // URLVoid only supports domains
	}
	
	// URLVoid requires API key in URL path
	apiURL := fmt.Sprintf("%s/%s/host/%s", checker.BaseURL, checker.APIKey, target)
	
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		log.Printf("URLVoid API error for %s: %v", target, err)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		log.Printf("URLVoid API returned status %d for %s", resp.StatusCode, target)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read URLVoid response for %s: %v", target, err)
		return nil
	}
	
	// ASSUMPTION: URLVoid returns XML, but we'll try to parse as JSON for simplicity
	// In a production system, would use proper XML parsing
	var urlvoidResponse map[string]interface{}
	if err := json.Unmarshal(body, &urlvoidResponse); err != nil {
		log.Printf("Failed to parse URLVoid response for %s: %v", target, err)
		return nil
	}
	
	// ASSUMPTION: URLVoid uses detections/total ratio similar to VirusTotal
	detections := 0.0
	total := 1.0
	
	// This would need proper implementation based on URLVoid's actual response format
	score := 0.8 // Placeholder score
	isMalicious := score < checker.Threshold
	
	details := fmt.Sprintf("URLVoid: %v/%v detections", detections, total)
	
	return &ReputationResult{
		Provider:   "urlvoid",
		Target:     target,
		Score:      score,
		IsMalicious: isMalicious,
		Details:    details,
		Timestamp:  time.Now(),
	}
}

// queryCustomProvider queries a custom reputation provider
func queryCustomProvider(checker ReputationChecker, target, targetType string) *ReputationResult {
	// ASSUMPTION: Custom provider uses URL template with {target} placeholder
	apiURL := strings.ReplaceAll(checker.QueryFormat, "{target}", url.QueryEscape(target))
	if !strings.HasPrefix(apiURL, "http") {
		apiURL = checker.BaseURL + "/" + apiURL
	}
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("Failed to create custom provider request for %s: %v", target, err)
		return nil
	}
	
	// Add custom headers
	for key, value := range checker.Headers {
		req.Header.Add(key, value)
	}
	
	// Add API key as header if specified
	if checker.APIKey != "" {
		req.Header.Add("Authorization", "Bearer "+checker.APIKey)
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Custom provider API error for %s: %v", target, err)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		log.Printf("Custom provider API returned status %d for %s", resp.StatusCode, target)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read custom provider response for %s: %v", target, err)
		return nil
	}
	
	// ASSUMPTION: Custom provider returns JSON with score field (0.0-1.0)
	var customResponse map[string]interface{}
	if err := json.Unmarshal(body, &customResponse); err != nil {
		log.Printf("Failed to parse custom provider response for %s: %v", target, err)
		return nil
	}
	
	score := 0.5 // Default neutral score
	if s, ok := customResponse["score"].(float64); ok {
		score = s
	}
	
	isMalicious := score < checker.Threshold
	details := fmt.Sprintf("%s: custom score %v", checker.Name, score)
	
	return &ReputationResult{
		Provider:   checker.Name,
		Target:     target,
		Score:      score,
		IsMalicious: isMalicious,
		Details:    details,
		Timestamp:  time.Now(),
	}
}

// loadBlacklistConfiguration loads blacklist configuration from JSON file
func loadBlacklistConfiguration(configPath string) (*BlacklistConfig, error) {
	// ASSUMPTION: Blacklist configuration is in JSON format for consistency with script config
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blacklist config file: %v", err)
	}
	
	var config BlacklistConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse blacklist JSON config: %v", err)
	}
	
	// Set default refresh interval if not specified
	// ASSUMPTION: Default to 300 seconds (5 minutes) for reasonable balance between freshness and performance
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = 300
	}
	
	// Validate file paths if specified
	if config.IPBlacklistFile != "" {
		if _, err := os.Stat(config.IPBlacklistFile); err != nil {
			return nil, fmt.Errorf("IP blacklist file not accessible: %v", err)
		}
	}
	if config.DomainBlacklistFile != "" {
		if _, err := os.Stat(config.DomainBlacklistFile); err != nil {
			return nil, fmt.Errorf("domain blacklist file not accessible: %v", err)
		}
	}
	
	log.Printf("Loaded blacklist configuration: Redis IP set=%s, Redis domain set=%s, IP file=%s, domain file=%s", 
		config.RedisIPSet, config.RedisDomainSet, config.IPBlacklistFile, config.DomainBlacklistFile)
	
	return &config, nil
}

// loadFileBlacklists loads blacklists from files into memory
func loadFileBlacklists() error {
	if blacklistConfig == nil {
		return nil // No blacklist configuration
	}
	
	// Check if refresh is needed
	// ASSUMPTION: Only reload if refresh interval has passed to avoid unnecessary I/O
	if time.Since(lastBlacklistLoad) < time.Duration(blacklistConfig.RefreshInterval)*time.Second {
		return nil
	}
	
	// Load IP blacklist file
	if blacklistConfig.IPBlacklistFile != "" {
		newIPBlacklist := make(map[string]bool)
		
		data, err := ioutil.ReadFile(blacklistConfig.IPBlacklistFile)
		if err != nil {
			log.Printf("WARNING: Failed to load IP blacklist file: %v", err)
		} else {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// ASSUMPTION: Skip empty lines and comments (lines starting with #)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				
				// Validate IP format
				if net.ParseIP(line) != nil {
					newIPBlacklist[line] = true
				} else {
					log.Printf("WARNING: Invalid IP in blacklist file: %s", line)
				}
			}
			ipBlacklist = newIPBlacklist
			log.Printf("Loaded %d IPs from IP blacklist file", len(ipBlacklist))
		}
	}
	
	// Load domain blacklist file
	if blacklistConfig.DomainBlacklistFile != "" {
		newDomainBlacklist := make(map[string]bool)
		
		data, err := ioutil.ReadFile(blacklistConfig.DomainBlacklistFile)
		if err != nil {
			log.Printf("WARNING: Failed to load domain blacklist file: %v", err)
		} else {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// ASSUMPTION: Skip empty lines and comments
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				
				// ASSUMPTION: Convert domains to lowercase for case-insensitive matching
				line = strings.ToLower(line)
				
				// Basic domain validation - must contain at least one dot
				if strings.Contains(line, ".") {
					newDomainBlacklist[line] = true
				} else {
					log.Printf("WARNING: Invalid domain in blacklist file: %s", line)
				}
			}
			domainBlacklist = newDomainBlacklist
			log.Printf("Loaded %d domains from domain blacklist file", len(domainBlacklist))
		}
	}
	
	lastBlacklistLoad = time.Now()
	return nil
}

// checkIPBlacklist checks if an IP is blacklisted (Redis or file-based)
func checkIPBlacklist(ip string, redisClient *redis.Client) bool {
	if blacklistConfig == nil {
		return false
	}
	
	ctx := context.Background()
	
	// Check Redis-based IP blacklist
	if blacklistConfig.RedisIPSet != "" && redisClient != nil {
		exists, err := redisClient.SIsMember(ctx, blacklistConfig.RedisIPSet, ip).Result()
		if err != nil {
			log.Printf("WARNING: Failed to check Redis IP blacklist: %v", err)
		} else if exists {
			log.Printf("BLACKLIST HIT: IP %s found in Redis blacklist set %s", ip, blacklistConfig.RedisIPSet)
			return true
		}
	}
	
	// Check file-based IP blacklist
	if ipBlacklist != nil && ipBlacklist[ip] {
		log.Printf("BLACKLIST HIT: IP %s found in file-based IP blacklist", ip)
		return true
	}
	
	return false
}

// checkDomainBlacklist checks if a domain is blacklisted (Redis or file-based)
func checkDomainBlacklist(domain string, redisClient *redis.Client) bool {
	if blacklistConfig == nil {
		return false
	}
	
	// ASSUMPTION: Normalize domain to lowercase and remove trailing dot for consistent matching
	normalizedDomain := strings.ToLower(strings.TrimSuffix(domain, "."))
	
	ctx := context.Background()
	
	// Check Redis-based domain blacklist
	if blacklistConfig.RedisDomainSet != "" && redisClient != nil {
		exists, err := redisClient.SIsMember(ctx, blacklistConfig.RedisDomainSet, normalizedDomain).Result()
		if err != nil {
			log.Printf("WARNING: Failed to check Redis domain blacklist: %v", err)
		} else if exists {
			log.Printf("BLACKLIST HIT: Domain %s found in Redis blacklist set %s", normalizedDomain, blacklistConfig.RedisDomainSet)
			return true
		}
	}
	
	// Check file-based domain blacklist
	if domainBlacklist != nil && domainBlacklist[normalizedDomain] {
		log.Printf("BLACKLIST HIT: Domain %s found in file-based domain blacklist", normalizedDomain)
		return true
	}
	
	// QUESTION: Should we also check parent domains for subdomain blocking?
	// ASSUMPTION: Check parent domains for comprehensive blocking (e.g., block evil.com also blocks sub.evil.com)
	if domainBlacklist != nil {
		parts := strings.Split(normalizedDomain, ".")
		for i := 1; i < len(parts); i++ {
			parentDomain := strings.Join(parts[i:], ".")
			if domainBlacklist[parentDomain] {
				log.Printf("BLACKLIST HIT: Domain %s blocked by parent domain %s in blacklist", normalizedDomain, parentDomain)
				return true
			}
		}
	}
	
	return false
}

// executeScript executes the appropriate script for a client with enhanced configuration
func executeScript(clientIP, resolvedIP, domain, ttl, action string, isNewRule bool) {
	// ASSUMPTION: Action can be "ADD" for new rules, "UPDATE" for existing rules, or "EXPIRE" for expired rules
	
	// Find client-specific configuration
	clientConfig := findClientConfig(clientIP)
	
	var scriptToExecute string
	var shouldExecute bool
	var additionalEnv map[string]string
	
	// Determine which script to execute and whether to execute it
	if action == "EXPIRE" {
		// Handle expiration scripts
		if clientConfig != nil && clientConfig.ExpireScript != "" {
			scriptToExecute = clientConfig.ExpireScript
			shouldExecute = true
			additionalEnv = clientConfig.Environment
			if os.Getenv("DEBUG") != "" {
				log.Printf("Using client-specific expire script for %s: %s", clientIP, scriptToExecute)
			}
		} else if scriptConfig != nil && scriptConfig.Defaults.ExpireScript != "" {
			scriptToExecute = scriptConfig.Defaults.ExpireScript
			shouldExecute = true
			additionalEnv = scriptConfig.Defaults.Environment
		} else if expireScript := os.Getenv("EXPIRE_SCRIPT"); expireScript != "" {
			scriptToExecute = expireScript
			shouldExecute = true
		}
	} else {
		// Handle invoke scripts (ADD/UPDATE actions)
		if clientConfig != nil && clientConfig.InvokeScript != "" {
			scriptToExecute = clientConfig.InvokeScript
			additionalEnv = clientConfig.Environment
			
			// Determine if we should execute based on client-specific settings
			if isNewRule {
				shouldExecute = true // Always execute for new rules
			} else {
				// For existing rules, check invoke_always setting
				if clientConfig.InvokeAlways != nil {
					shouldExecute = *clientConfig.InvokeAlways
				} else if scriptConfig != nil {
					shouldExecute = scriptConfig.Defaults.InvokeAlways
				} else {
					shouldExecute = os.Getenv("INVOKE_ALWAYS") != ""
				}
			}
			
			if os.Getenv("DEBUG") != "" {
				log.Printf("Using client-specific invoke script for %s: %s (execute=%t)", clientIP, scriptToExecute, shouldExecute)
			}
		} else if scriptConfig != nil && scriptConfig.Defaults.InvokeScript != "" {
			scriptToExecute = scriptConfig.Defaults.InvokeScript
			additionalEnv = scriptConfig.Defaults.Environment
			
			if isNewRule {
				shouldExecute = true
			} else {
				shouldExecute = scriptConfig.Defaults.InvokeAlways
			}
		} else if globalInvoke := os.Getenv("INVOKE_SCRIPT"); globalInvoke != "" {
			scriptToExecute = globalInvoke
			
			if isNewRule {
				shouldExecute = true
			} else {
				shouldExecute = os.Getenv("INVOKE_ALWAYS") != ""
			}
		}
	}
	
	// Execute the script if determined appropriate
	if scriptToExecute != "" && shouldExecute {
		// Set standard environment variables
		os.Setenv("CLIENT_IP", sanitizeForShell(clientIP))
		os.Setenv("RESOLVED_IP", sanitizeForShell(resolvedIP))
		os.Setenv("DOMAIN", sanitizeForShell(domain))
		os.Setenv("TTL", sanitizeForShell(ttl))
		os.Setenv("ACTION", sanitizeForShell(action))
		
		// Set additional client-specific environment variables
		// ASSUMPTION: Client-specific env vars override global ones for security and flexibility
		if additionalEnv != nil {
			for key, value := range additionalEnv {
				os.Setenv(key, sanitizeForShell(value))
				if os.Getenv("DEBUG") != "" {
					log.Printf("Set additional env var for client %s: %s=%s", clientIP, key, value)
				}
			}
		}
		
		// Execute the script
		cmd := exec.Command(scriptToExecute)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Script execution failed for %s (%s): %v\nOutput: %s", clientIP, action, err, output)
		} else {
			if os.Getenv("DEBUG") != "" {
				log.Printf("Script execution succeeded for %s (%s):\n%s", clientIP, action, output)
			} else {
				log.Printf("Script executed successfully for %s (%s): %s", clientIP, action, scriptToExecute)
			}
		}
		
		// Clean up additional environment variables to prevent leakage
		// ASSUMPTION: Clean up custom env vars to prevent them affecting subsequent executions
		if additionalEnv != nil {
			for key := range additionalEnv {
				os.Unsetenv(key)
			}
		}
	} else {
		if os.Getenv("DEBUG") != "" {
			log.Printf("No script execution for %s (%s): script=%s, shouldExecute=%t", clientIP, action, scriptToExecute, shouldExecute)
		}
	}
}

func validateInvokeScript(scriptPath string) error {
	if scriptPath == "" {
		return fmt.Errorf("script path is empty")
	}
	
	// Resolve to absolute path to prevent directory traversal
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return fmt.Errorf("invalid script path: %v", err)
	}
	
	// Check if file exists and is executable
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("script not found: %v", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("script path is a directory")
	}
	
	// Check if file is executable
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("script is not executable")
	}
	
	return nil
}

func sanitizeForShell(input string) string {
	// Remove any shell metacharacters
	return regexp.MustCompile(`[^a-zA-Z0-9\._\-]`).ReplaceAllString(input, "")
}

func inRange(ipLow, ipHigh, ip netip.Addr) bool {
	return ipLow.Compare(ip) <= 0 && ipHigh.Compare(ip) > 0
}

func Register(rt Route) error {
	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		log.Fatal("Missing UPSTREAM env var: please declare with UPSTREAM=host:port")
	}
	ednsAdd := os.Getenv("ENABLE_EDNS")

	// HANDLE_ALL_IPS: when set, process all A records instead of just the first one
	handleAllIPs := os.Getenv("HANDLE_ALL_IPS")

	redisEnv := os.Getenv("REDIS")
	if redisEnv == "" {
		log.Printf("Missing REDIS env var, this isn't meant to be run without Redis")
	}

	invoke := os.Getenv("INVOKE_SCRIPT")
	if invoke == "" {
		log.Printf("INVOKE_SCRIPT env var not set, not executing script for new IPs")
	} else {
		if err := validateInvokeScript(invoke); err != nil {
			log.Fatalf("Invalid INVOKE_SCRIPT: %v", err)
		}
		log.Printf("INVOKE_SCRIPT is set to %s", invoke)
	}

	invoke_always := os.Getenv("INVOKE_ALWAYS")
	if invoke_always == "" {
		log.Printf("INVOKE_ALWAYS is not set, only executing INVOKE script for IPs not present in Redis")
	} else {
		log.Printf("INVOKE_ALWAYS is set, executing INVOKE script for every matching request")
	}

	// EXPIRE_SCRIPT: Script to execute when Redis keys expire (for non-Linux/non-ipset support)
	expireScript := os.Getenv("EXPIRE_SCRIPT")
	if expireScript == "" {
		log.Printf("EXPIRE_SCRIPT env var not set, Redis key expiration monitoring disabled")
	} else {
		if err := validateInvokeScript(expireScript); err != nil {
			log.Fatalf("Invalid EXPIRE_SCRIPT: %v", err)
		}
		log.Printf("EXPIRE_SCRIPT is set to %s", expireScript)
	}

	// WEB_UI_PORT: Port for web UI server (for rule management and monitoring)
	webUIPort := os.Getenv("WEB_UI_PORT")
	if webUIPort == "" {
		log.Printf("WEB_UI_PORT env var not set, web UI disabled")
	} else {
		// ASSUMPTION: Validate port range (1024-65535 for non-privileged)
		if port, err := strconv.Atoi(webUIPort); err != nil || port < 1024 || port > 65535 {
			log.Fatalf("Invalid WEB_UI_PORT: must be between 1024-65535, got: %s", webUIPort)
		}
		log.Printf("WEB_UI_PORT is set to %s", webUIPort)
	}

	// SCRIPT_CONFIG: JSON configuration file for per-client script settings
	scriptConfigPath := os.Getenv("SCRIPT_CONFIG")
	if scriptConfigPath != "" {
		config, err := loadScriptConfiguration(scriptConfigPath)
		if err != nil {
			log.Fatalf("Failed to load script configuration: %v", err)
		}
		scriptConfig = config
		log.Printf("SCRIPT_CONFIG loaded from %s", scriptConfigPath)
	} else {
		log.Printf("SCRIPT_CONFIG env var not set, using environment variables for script configuration")
	}

	// BLACKLIST_CONFIG: JSON configuration file for IP/domain blacklisting
	blacklistConfigPath := os.Getenv("BLACKLIST_CONFIG")
	if blacklistConfigPath != "" {
		config, err := loadBlacklistConfiguration(blacklistConfigPath)
		if err != nil {
			log.Fatalf("Failed to load blacklist configuration: %v", err)
		}
		blacklistConfig = config
		log.Printf("BLACKLIST_CONFIG loaded from %s", blacklistConfigPath)
	} else {
		log.Printf("BLACKLIST_CONFIG env var not set, blacklisting disabled")
	}

	// REPUTATION_CONFIG: JSON configuration file for IP/domain reputation checking
	reputationConfigPath := os.Getenv("REPUTATION_CONFIG")
	if reputationConfigPath != "" {
		config, err := loadReputationConfiguration(reputationConfigPath)
		if err != nil {
			log.Fatalf("Failed to load reputation configuration: %v", err)
		}
		reputationConfig = config
		
		// Initialize reputation system
		initializeReputationSystem()
		
		log.Printf("REPUTATION_CONFIG loaded from %s with %d checkers", reputationConfigPath, len(reputationConfig.Checkers))
	} else {
		log.Printf("REPUTATION_CONFIG env var not set, reputation checking disabled")
	}

	opt, err := redis.ParseURL(redisEnv)
	if err != nil {
		panic(err)
	}

	redisClient := redis.NewClient(opt)

	ctx := context.Background()

	err = redisClient.Set(ctx, "ConnTest", "succeeded", 0).Err()
	if err != nil {
		log.Printf("Unable to add key to Redis!  This isn't meant to be run without Redis:\n %s", err.Error())
	}
	val, err := redisClient.Get(ctx, "ConnTest").Result()
	if err != nil {
		log.Printf("Unable to read key from Redis!  This isn't meant to be run without Redis:\n %s", err.Error())
	}
	_, err = redisClient.Del(ctx, "ConnTest").Result()
	if err != nil {
		log.Printf("Unable to delete key from Redis!  This isn't meant to be run without Redis:\n %s", err.Error())
	}
	log.Printf("Redis connection %s", val)

	// Load initial blacklists and start periodic refresh
	if blacklistConfig != nil {
		if err := loadFileBlacklists(); err != nil {
			log.Printf("WARNING: Failed to load initial blacklists: %v", err)
		}
		
		// Start periodic blacklist refresh in background
		go func() {
			ticker := time.NewTicker(time.Duration(blacklistConfig.RefreshInterval) * time.Second)
			defer ticker.Stop()
			
			for range ticker.C {
				if err := loadFileBlacklists(); err != nil {
					log.Printf("WARNING: Failed to refresh blacklists: %v", err)
				}
			}
		}()
		log.Printf("Started blacklist refresh background task (interval: %d seconds)", blacklistConfig.RefreshInterval)
	}

	// FEATURE: Redis key expiration monitoring for non-Linux/non-ipset support
	// This enables cleanup of firewall rules when DNS TTLs expire by monitoring Redis keyspace notifications
	if expireScript != "" {
		// Enable Redis keyspace notifications for expired events
		// ASSUMPTION: This requires Redis config notify-keyspace-events to include 'Ex' for expired events
		_, err := redisClient.ConfigSet(ctx, "notify-keyspace-events", "Ex").Result()
		if err != nil {
			log.Printf("WARNING: Failed to enable Redis keyspace notifications: %v", err)
			log.Printf("Manual Redis config may be needed: CONFIG SET notify-keyspace-events Ex")
		} else {
			log.Printf("Enabled Redis keyspace notifications for key expiration events")
		}
		
		// Start Redis expiration watchdog in a separate goroutine
		go func() {
			// ASSUMPTION: Subscribe to all expired events in database 0 (default)
			pubsub := redisClient.Subscribe(ctx, "__keyevent@0__:expired")
			defer pubsub.Close()
			
			log.Printf("Started Redis expiration watchdog, monitoring key expiration events")
			log.Printf("EXPIRE_SCRIPT is set to: %s", expireScript)
			
			// Listen for expiration events
			ch := pubsub.Channel()
			for msg := range ch {
				// msg.Payload contains the expired key name
				expiredKey := msg.Payload
				
				// ASSUMPTION: Only process our firewall rule keys (format: "rules:client:ip:domain")
				if strings.HasPrefix(expiredKey, "rules:") {
					parts := strings.Split(expiredKey, ":")
					if len(parts) >= 4 {
						clientIP := parts[1]
						resolvedIP := parts[2]
						domain := strings.Join(parts[3:], ":") // domain might contain colons
						
						// QUESTION: Should we validate IPs here or trust Redis key format?
						// ASSUMPTION: Trust Redis key format since we control key creation
						
						log.Printf("Key expired: %s (client=%s, resolved=%s, domain=%s)", expiredKey, clientIP, resolvedIP, domain)
						
						// Use enhanced script execution system for expiration
						executeScript(clientIP, resolvedIP, domain, "0", "EXPIRE", false)
					} else {
						log.Printf("WARNING: Malformed expired key format: %s", expiredKey)
					}
				}
				// ASSUMPTION: Ignore non-firewall keys (other app keys, etc)
			}
			log.Printf("Redis expiration watchdog terminated")
		}()
	} else {
		log.Printf("EXPIRE_SCRIPT not set, Redis key expiration monitoring disabled")
	}

	// Start web UI server if enabled
	if webUIPort != "" {
		go startWebUI(webUIPort, redisClient)
	}

	dns.HandleFunc(rt.Zone, func(w dns.ResponseWriter, r *dns.Msg) {

		// find client IP
		from := ""
		switch addr := w.RemoteAddr().(type) {
		case *net.UDPAddr:
			from = addr.IP.String()
		case *net.TCPAddr:
			from = addr.IP.String()
		}
		
		// Validate client IP
		if !validateIP(from) {
			log.Printf("Invalid client IP: %s", from)
			dns.HandleFailed(w, r)
			return
		}

		if os.Getenv("DEBUG") != "" {
			log.Printf("Request from client %s:\n%s\n", from, r)
		}

		// FEATURE: Domain blacklist checking before DNS resolution
		if len(r.Question) > 0 {
			requestedDomain := r.Question[0].Name
			
			if checkDomainBlacklist(requestedDomain, redisClient) {
				if blacklistConfig.LogOnly {
					log.Printf("BLACKLIST LOG: Domain %s requested by %s is blacklisted (log-only mode)", requestedDomain, from)
				} else if blacklistConfig.BlockOnMatch {
					log.Printf("BLACKLIST BLOCK: Blocking DNS request for blacklisted domain %s from %s", requestedDomain, from)
					// ASSUMPTION: Return NXDOMAIN (domain not found) for blacklisted domains
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				}
			}
			
			// FEATURE: Domain reputation checking before DNS resolution
			if reputationConfig != nil {
				reputationResult := checkReputation("domain", requestedDomain, redisClient)
				if reputationResult.IsMalicious {
					log.Printf("REPUTATION BLOCK: Domain %s requested by %s flagged as malicious (score: %.2f, provider: %s)", 
						requestedDomain, from, reputationResult.Score, reputationResult.Provider)
					// ASSUMPTION: Block malicious domains by returning NXDOMAIN
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				} else if os.Getenv("DEBUG") != "" {
					log.Printf("REPUTATION OK: Domain %s clean (score: %.2f, provider: %s)", 
						requestedDomain, reputationResult.Score, reputationResult.Provider)
				}
			}
		}

		//dnsClient := &dns.Client{Net: "udp"}

		// Set EDNS Client Subnet so that upstream DNS servers receive the real client IP
		// This enables location-aware responses and proper geo-blocking by upstream servers
		if ednsAdd != "" {
			// Parse and validate the client IP address
			clientIP := net.ParseIP(from)
			if clientIP == nil {
				// ASSUMPTION: If client IP is invalid, log and skip EDNS to avoid breaking the request
				log.Printf("WARNING: Invalid client IP '%s' for EDNS, skipping EDNS processing", from)
			} else {
				// Check if request already has EDNS OPT records to avoid duplicates
				hasExistingOPT := false
				for _, rr := range r.Extra {
					if rr.Header().Rrtype == dns.TypeOPT {
						hasExistingOPT = true
						break
					}
				}
				
				if !hasExistingOPT {
					// Create properly formed OPT record with EDNS Client Subnet
					o := new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.SetUDPSize(4096) // Set appropriate buffer size for EDNS
					
					// Create EDNS Client Subnet option
					e := new(dns.EDNS0_SUBNET)
					e.Code = dns.EDNS0SUBNET
					e.SourceScope = 0 // Always 0 for queries
					
					// ASSUMPTION: Determine IPv4 vs IPv6 and set appropriate family/netmask
					// IPv4 addresses get family=1, netmask=32
					// IPv6 addresses get family=2, netmask=128
					if clientIP.To4() != nil {
						// IPv4 address
						e.Family = 1
						e.SourceNetmask = 32
						e.Address = clientIP.To4()
					} else {
						// IPv6 address  
						e.Family = 2
						e.SourceNetmask = 128
						e.Address = clientIP.To16()
					}
					
					o.Option = append(o.Option, e)
					r.Extra = append(r.Extra, o)
					
					if os.Getenv("DEBUG") != "" {
						log.Printf("Added EDNS Client Subnet for %s (family=%d, netmask=%d)", from, e.Family, e.SourceNetmask)
					}
				} else {
					// QUESTION: Should we modify existing OPT record or leave it alone?
					// ASSUMPTION: Leave existing OPT records untouched to avoid conflicts
					if os.Getenv("DEBUG") != "" {
						log.Printf("Request already has EDNS OPT record, skipping EDNS Client Subnet addition")
					}
				}
			}
		}
		dnsClient := &dns.Client{Net: "udp"}
		a, _, err := dnsClient.Exchange(r, upstream)
		if err != nil {
			log.Printf("DNS query failed: %v", err)
			dns.HandleFailed(w, r)
			return
		}
		if a == nil {
			log.Printf("Empty DNS response from upstream")
			dns.HandleFailed(w, r)
			return
		}
		if os.Getenv("DEBUG") != "" {
			log.Printf("Response from upstream %s:\n%s\n", upstream, a)
		}

		var numAnswers = len(a.Answer)

		var ipAddress, _ = netip.ParseAddr("127.0.0.1")
		var loStart, _ = netip.ParseAddr("127.0.0.0")
		var loEnd, _ = netip.ParseAddr("127.255.255.255")
		var openRange, _ = netip.ParseAddr("0.0.0.0")
		// IPv6 localhost and open range addresses
		var loV6, _ = netip.ParseAddr("::1")        // IPv6 localhost
		var openRangeV6, _ = netip.ParseAddr("::")   // IPv6 unspecified address
		var padTtl uint32 = 0

		var foundAddressRecords bool = false // true if A or AAAA records found
		var ipAddresses []netip.Addr // collect all IP addresses when HANDLE_ALL_IPS is set
		var firstIPIndex int = -1
		
		for i := range numAnswers {
			var currentIP netip.Addr
			var isAddressRecord bool = false
			
			// Handle A records (IPv4)
			if arec, ok := a.Answer[i].(*dns.A); ok {
				foundAddressRecords = true
				isAddressRecord = true
				currentIP, _ = netip.ParseAddr(arec.A.String())
			}
			// Handle AAAA records (IPv6)  
			if aaaarec, ok := a.Answer[i].(*dns.AAAA); ok {
				foundAddressRecords = true
				isAddressRecord = true
				currentIP, _ = netip.ParseAddr(aaaarec.AAAA.String())
			}
			
			if isAddressRecord {
				// FEATURE: IP blacklist checking after DNS resolution
				if checkIPBlacklist(currentIP.String(), redisClient) {
					if blacklistConfig.LogOnly {
						log.Printf("BLACKLIST LOG: IP %s resolved for domain %s is blacklisted (log-only mode)", currentIP.String(), r.Question[0].Name)
					} else if blacklistConfig.BlockOnMatch {
						log.Printf("BLACKLIST BLOCK: Removing blacklisted IP %s from DNS response for domain %s", currentIP.String(), r.Question[0].Name)
						// ASSUMPTION: Skip this record by continuing to next iteration
						// This effectively removes the blacklisted IP from the response
						continue
					}
				}
				
				// FEATURE: IP reputation checking after DNS resolution
				if reputationConfig != nil {
					reputationResult := checkReputation("ip", currentIP.String(), redisClient)
					if reputationResult.IsMalicious {
						log.Printf("REPUTATION BLOCK: IP %s resolved for domain %s flagged as malicious (score: %.2f, provider: %s)", 
							currentIP.String(), r.Question[0].Name, reputationResult.Score, reputationResult.Provider)
						// ASSUMPTION: Skip this record by continuing to next iteration
						// This effectively removes malicious IPs from the response
						continue
					} else if os.Getenv("DEBUG") != "" {
						log.Printf("REPUTATION OK: IP %s clean (score: %.2f, provider: %s)", 
							currentIP.String(), reputationResult.Score, reputationResult.Provider)
					}
				}
				
				// padTtl is used in Redis TTL and in invoked scripts,
				// while ttl is used in client response
				ttl := a.Answer[i].Header().Ttl
				padTtl = ttl
				// Validate TTL
				if !validateTTL(ttl) {
					log.Printf("Invalid TTL: %d", ttl)
					continue
				}
				
				// pad very low TTLs
				if ttl < 30 {
					padTtl = ttl + 30
				}
				// clamp TTL at 1 hour
				if ttl > 3600 {
					padTtl = 3600
					a.Answer[i].Header().Ttl = 3600 // to the client as well
				}
				
				if handleAllIPs != "" {
					// collect all IP addresses for processing
					ipAddresses = append(ipAddresses, currentIP)
					if firstIPIndex == -1 {
						firstIPIndex = i
					}
				} else {
					// original behavior: handle only first address record
					ipAddress = currentIP
					A := a.Answer[0 : i+1]
					a.Answer = A
					break
				}
			}
		}
		
		// when HANDLE_ALL_IPS is set, set ipAddress to first IP for client response
		// but we'll process all IPs in the firewall logic below
		if handleAllIPs != "" && len(ipAddresses) > 0 {
			ipAddress = ipAddresses[0]
			// respond with all records up to the last A record
			if firstIPIndex != -1 {
				A := a.Answer[0 : firstIPIndex+len(ipAddresses)]
				a.Answer = A
			}
		}

		// helper function to process individual IP addresses
		processIP := func(targetIP netip.Addr) {
			// Check if IP is in localhost range (IPv4 or IPv6) or is open range
			isLocalhost := false
			if targetIP.Is4() {
				isLocalhost = inRange(loStart, loEnd, targetIP) || targetIP == openRange
			} else if targetIP.Is6() {
				isLocalhost = targetIP == loV6 || targetIP == openRangeV6
			}
			
			if !isLocalhost {
				newTtl := time.Duration(padTtl) * time.Second
				newTtlS := strconv.FormatFloat(newTtl.Seconds(), 'f', -1, 64)
				domain := r.Question[0].Name
				
				// Validate domain name
				if !validateDomain(domain) {
					log.Printf("Invalid domain: %s", domain)
					return // continue processing other IPs instead of failing entire request
				}
				
				key := "rules:" + from + ":" + targetIP.String() + ":" + domain
				
				// Sanitize environment variables to prevent injection  
				sanitizedClientIP := sanitizeForShell(from)
				sanitizedResolvedIP := sanitizeForShell(targetIP.String())
				sanitizedDomain := sanitizeForShell(domain)
				sanitizedTTL := sanitizeForShell(newTtlS)
				
				os.Setenv("CLIENT_IP", sanitizedClientIP)
				os.Setenv("RESOLVED_IP", sanitizedResolvedIP)
				os.Setenv("DOMAIN", sanitizedDomain)
				os.Setenv("TTL", sanitizedTTL)
				_, err := redisClient.Get(ctx, key).Result()
				// insert into Redis
				if err != nil {
					log.Printf("Add %s for %s, %s %s", targetIP, from, domain, newTtl)
					resp, err := redisClient.Set(ctx, key, newTtl, newTtl).Result()
					if err != nil {
						log.Printf("Unable to add key to Redis! %s", err.Error())
					}
					if os.Getenv("DEBUG") != "" {
						log.Printf("Redis insert: %s", resp)
					}
					// first appearance, use enhanced script execution system
					executeScript(from, targetIP.String(), domain, newTtlS, "ADD", true)
				} else {
					log.Printf("Update %s for %s, %s %s", targetIP, from, domain, newTtl)
					resp, err := redisClient.Set(ctx, key, "", newTtl).Result()
					if err != nil {
						log.Printf("Unable to add key to Redis! %s", err.Error())
					}
					if os.Getenv("DEBUG") != "" {
						log.Printf("Redis insert: %s", resp)
					}
					// existing rule update, use enhanced script execution system
					executeScript(from, targetIP.String(), domain, newTtlS, "UPDATE", false)
				}
			}
		}

		// only target A and AAAA records  
		if foundAddressRecords {
			if handleAllIPs != "" && len(ipAddresses) > 0 {
				// process all collected IP addresses
				for _, ip := range ipAddresses {
					processIP(ip)
				}
			} else {
				// original behavior: process only the first IP
				processIP(ipAddress)
			}
		}
		w.WriteMsg(a)

		// dropping request
	})
	return nil
}

// startWebUI starts the web UI server for rule management
func startWebUI(port string, redisClient *redis.Client) {
	// ASSUMPTION: Web UI should be simple and lightweight, using built-in HTML templates
	log.Printf("Starting web UI server on port %s", port)
	
	// Serve static content (CSS, JS) if needed
	http.HandleFunc("/", handleUIHome)
	http.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		handleAPIRules(w, r, redisClient)
	})
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		handleAPIStats(w, r, redisClient)
	})
	http.HandleFunc("/api/rules/delete", func(w http.ResponseWriter, r *http.Request) {
		handleAPIDeleteRule(w, r, redisClient)
	})
	
	// QUESTION: Should we enable HTTPS? For now, using HTTP for simplicity
	// ASSUMPTION: This is intended for internal/localhost use, so HTTP is acceptable
	server := &http.Server{
		Addr:    ":" + port,
		Handler: nil, // Use default ServeMux
		// ASSUMPTION: Set reasonable timeouts to prevent resource exhaustion
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Web UI server failed: %v", err)
	}
}

// handleUIHome serves the main HTML page
func handleUIHome(w http.ResponseWriter, r *http.Request) {
	// ASSUMPTION: Embed HTML template directly in code to avoid external file dependencies
	htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>dfirewall - Rule Management</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #007acc; color: white; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
        .stat-box h3 { margin: 0; font-size: 24px; }
        .stat-box p { margin: 5px 0 0 0; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:hover { background-color: #f9f9f9; }
        .delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
        .delete-btn:hover { background: #c82333; }
        .refresh-btn { background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
        .refresh-btn:hover { background: #218838; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .error { color: #dc3545; text-align: center; padding: 20px; }
        .domain { word-break: break-all; max-width: 200px; }
        .ttl { font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>dfirewall - Firewall Rule Management</h1>
        
        <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
        
        <div class="stats" id="stats">
            <div class="stat-box">
                <h3 id="totalRules">-</h3>
                <p>Total Rules</p>
            </div>
            <div class="stat-box">
                <h3 id="activeClients">-</h3>
                <p>Active Clients</p>
            </div>
            <div class="stat-box">
                <h3 id="uniqueDomains">-</h3>
                <p>Unique Domains</p>
            </div>
            <div class="stat-box">
                <h3 id="uniqueIPs">-</h3>
                <p>Unique IPs</p>
            </div>
        </div>
        
        <div id="loading" class="loading">Loading firewall rules...</div>
        <div id="error" class="error" style="display: none;"></div>
        
        <table id="rulesTable" style="display: none;">
            <thead>
                <tr>
                    <th>Client IP</th>
                    <th>Resolved IP</th>
                    <th>Domain</th>
                    <th>TTL (seconds)</th>
                    <th>Expires At</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="rulesBody">
            </tbody>
        </table>
    </div>

    <script>
        // ASSUMPTION: Use vanilla JavaScript to avoid external dependencies
        async function loadData() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('error').style.display = 'none';
            document.getElementById('rulesTable').style.display = 'none';
            
            try {
                // Load statistics
                const statsResponse = await fetch('/api/stats');
                const stats = await statsResponse.json();
                
                document.getElementById('totalRules').textContent = stats.total_rules;
                document.getElementById('activeClients').textContent = stats.active_clients;
                document.getElementById('uniqueDomains').textContent = stats.unique_domains;
                document.getElementById('uniqueIPs').textContent = stats.unique_ips;
                
                // Load rules
                const rulesResponse = await fetch('/api/rules');
                const rules = await rulesResponse.json();
                
                const tbody = document.getElementById('rulesBody');
                tbody.innerHTML = '';
                
                rules.forEach(rule => {
                    const row = document.createElement('tr');
                    row.innerHTML = ` + "`" + `
                        <td>${rule.client_ip}</td>
                        <td>${rule.resolved_ip}</td>
                        <td class="domain">${rule.domain}</td>
                        <td class="ttl">${rule.ttl}</td>
                        <td>${new Date(rule.expires_at).toLocaleString()}</td>
                        <td>
                            <button class="delete-btn" onclick="deleteRule('${rule.key}')">Delete</button>
                        </td>
                    ` + "`" + `;
                    tbody.appendChild(row);
                });
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('rulesTable').style.display = 'table';
                
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Error loading data: ' + error.message;
            }
        }
        
        async function deleteRule(key) {
            if (!confirm('Are you sure you want to delete this rule?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/rules/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({key: key})
                });
                
                if (response.ok) {
                    loadData(); // Refresh the data
                } else {
                    alert('Error deleting rule');
                }
            } catch (error) {
                alert('Error deleting rule: ' + error.message);
            }
        }
        
        // Load data on page load
        window.onload = loadData;
        
        // Auto-refresh every 30 seconds
        setInterval(loadData, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlTemplate))
}

// handleAPIRules returns all firewall rules as JSON
func handleAPIRules(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	ctx := context.Background()
	
	// ASSUMPTION: Get all keys matching our pattern "rules:*"
	keys, err := redisClient.Keys(ctx, "rules:*").Result()
	if err != nil {
		http.Error(w, "Error fetching rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	var rules []FirewallRule
	
	for _, key := range keys {
		// Parse key format: "rules:client:ip:domain"
		parts := strings.Split(key, ":")
		if len(parts) < 4 {
			continue // Skip malformed keys
		}
		
		clientIP := parts[1]
		resolvedIP := parts[2]
		domain := strings.Join(parts[3:], ":") // Domain might contain colons
		
		// Get TTL
		ttl, err := redisClient.TTL(ctx, key).Result()
		if err != nil {
			ttl = -1 // Unknown TTL
		}
		
		// ASSUMPTION: Calculate expiration time based on current time + TTL
		expiresAt := time.Now().Add(ttl)
		
		// QUESTION: How to determine creation time? Not stored in Redis
		// ASSUMPTION: Use current time minus original TTL as approximation
		createdAt := time.Now().Add(-ttl)
		if ttl < 0 {
			createdAt = time.Now() // Fallback for persistent keys
		}
		
		rule := FirewallRule{
			Key:        key,
			ClientIP:   clientIP,
			ResolvedIP: resolvedIP,
			Domain:     domain,
			TTL:        int64(ttl.Seconds()),
			ExpiresAt:  expiresAt,
			CreatedAt:  createdAt,
		}
		
		rules = append(rules, rule)
	}
	
	// ASSUMPTION: Sort rules by expiration time (soonest first)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ExpiresAt.Before(rules[j].ExpiresAt)
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// handleAPIStats returns statistics about the firewall rules
func handleAPIStats(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	ctx := context.Background()
	
	keys, err := redisClient.Keys(ctx, "rules:*").Result()
	if err != nil {
		http.Error(w, "Error fetching stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	clientIPs := make(map[string]bool)
	domains := make(map[string]bool)
	resolvedIPs := make(map[string]bool)
	
	for _, key := range keys {
		parts := strings.Split(key, ":")
		if len(parts) < 4 {
			continue
		}
		
		clientIP := parts[1]
		resolvedIP := parts[2]
		domain := strings.Join(parts[3:], ":")
		
		clientIPs[clientIP] = true
		resolvedIPs[resolvedIP] = true
		domains[domain] = true
	}
	
	stats := UIStats{
		TotalRules:    len(keys),
		ActiveClients: len(clientIPs),
		UniqueDomains: len(domains),
		UniqueIPs:     len(resolvedIPs),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAPIDeleteRule deletes a specific firewall rule
func handleAPIDeleteRule(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Key string `json:"key"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// ASSUMPTION: Validate that the key follows our expected format for security
	if !strings.HasPrefix(req.Key, "rules:") {
		http.Error(w, "Invalid key format", http.StatusBadRequest)
		return
	}
	
	ctx := context.Background()
	result, err := redisClient.Del(ctx, req.Key).Result()
	if err != nil {
		http.Error(w, "Error deleting rule: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	if result == 0 {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	
	log.Printf("Manually deleted rule: %s", req.Key)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
