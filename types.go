package main

import (
	"net"
	"time"
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

// ClientRules represents rules grouped by client IP
type ClientRules struct {
	ClientIP              string         `json:"client_ip"`
	RuleCount             int            `json:"rule_count"`
	Rules                 []FirewallRule `json:"rules"`
	LastUpdated           time.Time      `json:"last_updated"`
	TTLGracePeriodSeconds uint32         `json:"ttl_grace_period_seconds"`
}

// GroupedRulesResponse represents the API response for client-grouped rules
type GroupedRulesResponse struct {
	TotalClients int           `json:"total_clients"`
	TotalRules   int           `json:"total_rules"`
	Clients      []ClientRules `json:"clients"`
}

// HistoricalLookup represents a single historical DNS lookup entry
type HistoricalLookup struct {
	Domain     string    `json:"domain"`
	ResolvedIP string    `json:"resolved_ip"`
	Timestamp  time.Time `json:"timestamp"`
	TTL        int64     `json:"ttl,omitempty"`
}

// ClientHistoryResponse represents the API response for client lookup history
type ClientHistoryResponse struct {
	ClientIP     string             `json:"client_ip"`
	TotalLookups int                `json:"total_lookups"`
	Lookups      []HistoricalLookup `json:"lookups"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
}

// ClientInfo represents summary information about a client
type ClientInfo struct {
	ClientIP         string    `json:"client_ip"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	TotalLookups     int64     `json:"total_lookups"`
	ActiveRuleCount  int64     `json:"active_rule_count,omitempty"`
}

// AllClientsResponse represents the API response for listing all clients
type AllClientsResponse struct {
	TotalClients int64        `json:"total_clients"`
	Clients      []ClientInfo `json:"clients"`
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
	// Whether to execute scripts synchronously (overrides global SYNC_SCRIPT_EXECUTION)
	SyncExecution *bool `json:"sync_execution,omitempty"`
	// TTL grace period in seconds for this client (overrides global TTL_GRACE_PERIOD_SECONDS)
	TTLGracePeriodSeconds *uint32 `json:"ttl_grace_period_seconds,omitempty"`
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
		InvokeScript          string            `json:"invoke_script,omitempty"`
		ExpireScript          string            `json:"expire_script,omitempty"`
		InvokeAlways          bool              `json:"invoke_always,omitempty"`
		SyncExecution         bool              `json:"sync_execution,omitempty"`
		TTLGracePeriodSeconds uint32            `json:"ttl_grace_period_seconds,omitempty"`
		Environment           map[string]string `json:"environment,omitempty"`
	} `json:"defaults"`
	// Per-client configurations (processed in order - first match wins)
	Clients []ClientScriptConfig `json:"clients"`
}

// AI Integration Data Structures :D

// AIConfig represents AI-powered features configuration
type AIConfig struct {
	// QUESTION: Should we support multiple AI providers (OpenAI, Claude, local models)?
	// ASSUMPTION: Starting with OpenAI API but designed for extensibility
	Enabled        bool   `json:"enabled"`           // Global AI features enable/disable
	Provider       string `json:"provider"`          // AI provider (openai, claude, local, etc.)
	APIKey         string `json:"api_key,omitempty"` // API key for cloud providers
	BaseURL        string `json:"base_url"`          // API base URL (for custom endpoints)
	Model          string `json:"model"`             // AI model to use (gpt-4, claude-3, etc.)
	Timeout        int    `json:"timeout"`           // Request timeout in seconds
	
	// Feature toggles
	DomainAnalysis    bool `json:"domain_analysis"`    // Analyze domains for malicious patterns
	TrafficAnomalies  bool `json:"traffic_anomalies"`  // Detect traffic anomalies
	ProactiveThreatHunting bool `json:"proactive_threat_hunting"` // Hunt for threats proactively
	
	// Analysis thresholds and parameters
	MinConfidence     float64 `json:"min_confidence"`     // Minimum confidence for threat detection (0.0-1.0)
	MaxAnalysisDelay  int     `json:"max_analysis_delay"` // Maximum delay before analysis in seconds
	CacheResults      bool    `json:"cache_results"`      // Cache AI analysis results
	CacheExpiration   int     `json:"cache_expiration"`   // Cache expiration in seconds
}

// AIAnalysisRequest represents a request for AI analysis
type AIAnalysisRequest struct {
	Target        string            `json:"target"`              // Target to analyze (IP or domain)
	Domain        string            `json:"domain,omitempty"`
	IP            string            `json:"ip,omitempty"`
	Context       string            `json:"context"`             // Request context for analysis
	ClientIP      string            `json:"client_ip,omitempty"` // Client making the request
	QueryType     string            `json:"query_type"`          // DNS query type (A, AAAA, etc.)
	Timestamp     time.Time         `json:"timestamp"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// AIAnalysisResult represents the result of AI analysis
type AIAnalysisResult struct {
	Target           string             `json:"target"`             // Target that was analyzed
	IsThreat         bool               `json:"is_threat"`
	IsMalicious      bool               `json:"is_malicious"`       // Whether target is malicious
	IsAnomaly        bool               `json:"is_anomaly"`         // Whether target shows anomalous behavior
	Confidence       float64            `json:"confidence"`         // 0.0 to 1.0
	ThreatScore      float64            `json:"threat_score"`       // 0.0 to 1.0 threat score
	ThreatType       string             `json:"threat_type"`        // malware, phishing, c2, etc.
	Explanation      string             `json:"explanation"`        // Human-readable explanation
	Reasoning        string             `json:"reasoning"`          // AI reasoning for the decision
	Recommendation   string             `json:"recommendation"`     // Recommended action
	TechnicalDetails map[string]string  `json:"technical_details"`  // Technical analysis details
	Severity         string             `json:"severity"`           // low, medium, high, critical
	Categories       []string           `json:"categories"`         // Threat categories
	IOCs             []string           `json:"iocs"`               // Indicators of Compromise
	RelatedThreats   []string           `json:"related_threats"`    // Related known threats
	
	// Analysis metadata
	Provider      string    `json:"provider"`       // AI provider used
	Model         string    `json:"model"`          // AI model used
	AnalysisTime  int       `json:"analysis_time"`  // Analysis time in milliseconds
	Timestamp     time.Time `json:"timestamp"`
	RequestID     string    `json:"request_id"`     // For tracking/debugging
	
	// Caching information
	FromCache     bool      `json:"from_cache"`
	CacheKey      string    `json:"cache_key,omitempty"`
}

// AITrafficPattern represents detected traffic patterns for anomaly detection
type AITrafficPattern struct {
	ClientIP         string            `json:"client_ip"`
	TimeWindow       string            `json:"time_window"`        // 1h, 24h, 7d, etc.
	RequestCount     int               `json:"request_count"`
	UniqueDomains    int               `json:"unique_domains"`
	UniqueIPs        int               `json:"unique_ips"`
	DomainFrequency  map[string]int    `json:"domain_frequency"`   // domain -> count
	IPFrequency      map[string]int    `json:"ip_frequency"`       // ip -> count
	QueryTypes       map[string]int    `json:"query_types"`        // query type -> count
	
	// Anomaly indicators
	AnomalyScore     float64           `json:"anomaly_score"`      // 0.0 to 1.0
	Indicators       []string          `json:"indicators"`         // List of anomaly indicators
	
	// Pattern classification
	PatternType      string            `json:"pattern_type"`       // normal, suspicious, malicious
	Behaviors        []string          `json:"behaviors"`          // beaconing, exfiltration, etc.
	
	// Temporal analysis
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	RequestSpacing   []int             `json:"request_spacing"`    // Milliseconds between requests
	
	// Statistical metrics
	Entropy          float64           `json:"entropy"`            // Domain name entropy
	AverageQPS       float64           `json:"average_qps"`        // Queries per second
	PeakQPS          float64           `json:"peak_qps"`
	
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// Custom Script Integration

// CustomScriptConfig represents configuration for user-provided validation scripts
type CustomScriptConfig struct {
	Enabled          bool              `json:"enabled"`            // Global enable/disable
	
	// Script execution settings
	UnifiedScript    string            `json:"unified_script"`     // Single script for both IP and domain validation
	IPScript         string            `json:"ip_script"`          // Script specifically for IP validation
	DomainScript     string            `json:"domain_script"`      // Script specifically for domain validation
	
	// Execution parameters
	Timeout          int               `json:"timeout"`            // Script timeout in seconds
	MaxConcurrent    int               `json:"max_concurrent"`     // Maximum concurrent script executions
	RetryAttempts    int               `json:"retry_attempts"`     // Number of retry attempts on failure
	RetryDelay       int               `json:"retry_delay"`        // Delay between retries in seconds
	
	// Caching settings
	CacheResults     bool              `json:"cache_results"`      // Cache script results
	CacheExpiration  int               `json:"cache_expiration"`   // Cache expiration in seconds
	
	// Environment and execution context
	Environment      map[string]string `json:"environment"`        // Environment variables for scripts
	WorkingDirectory string            `json:"working_directory"`  // Working directory for script execution
	
	// Error handling
	FailOpen         bool              `json:"fail_open"`          // Allow on script failure (true) or block (false)
	LogResults       bool              `json:"log_results"`        // Log script results for debugging
}

// CustomScriptResult represents the result of custom script execution
type CustomScriptResult struct {
	// Script execution details
	ScriptPath       string            `json:"script_path"`
	Target           string            `json:"target"`             // IP or domain that was tested
	ExitCode         int               `json:"exit_code"`
	
	// Result interpretation
	IsAllowed        bool              `json:"is_allowed"`         // true = pass/allow, false = fail/block
	Reason           string            `json:"reason"`             // Human-readable reason
	
	// Execution metadata  
	ExecutionTime    int               `json:"execution_time"`     // Execution time in milliseconds
	Timestamp        time.Time         `json:"timestamp"`
	RetryCount       int               `json:"retry_count"`        // Number of retries performed
	
	// Script output
	Stdout           string            `json:"stdout,omitempty"`
	Stderr           string            `json:"stderr,omitempty"`
	
	// Caching information
	FromCache        bool              `json:"from_cache"`
	CacheKey         string            `json:"cache_key,omitempty"`
	
	// Error information
	Error            string            `json:"error,omitempty"`    // Error message if execution failed
}

// Blacklist Configuration

// BlacklistConfig represents IP/domain blacklist configuration
type BlacklistConfig struct {
	Enabled       bool     `json:"enabled"`        // Global blacklist enable/disable
	IPBlacklist   []string `json:"ip_blacklist"`   // List of blacklisted IPs/CIDRs
	DomainBlacklist []string `json:"domain_blacklist"` // List of blacklisted domains/patterns
	
	// File-based blacklists (one entry per line)
	IPBlacklistFile     string `json:"ip_blacklist_file,omitempty"`
	DomainBlacklistFile string `json:"domain_blacklist_file,omitempty"`
	
	// Dynamic blacklist settings (Redis-based)
	UseRedisBlacklist   bool   `json:"use_redis_blacklist"`   // Use Redis for dynamic blacklists
	RedisIPKey          string `json:"redis_ip_key"`          // Redis key for IP blacklist
	RedisDomainKey      string `json:"redis_domain_key"`      // Redis key for domain blacklist
	
	// Pattern matching settings
	UseRegex            bool   `json:"use_regex"`             // Enable regex pattern matching
	CaseSensitive       bool   `json:"case_sensitive"`        // Case-sensitive matching
	
	// Refresh settings
	RefreshInterval     int    `json:"refresh_interval"`      // Refresh interval in seconds
	LogOnly             bool   `json:"log_only"`              // Only log matches, don't block
	BlockOnMatch        bool   `json:"block_on_match"`        // Block when blacklist matches
}

// Reputation Checking

// ReputationChecker represents a single reputation checker service
type ReputationChecker struct {
	Name        string            `json:"name"`         // Friendly name
	Type        string            `json:"type"`         // ip, domain, or both
	URL         string            `json:"url"`          // API endpoint URL template
	BaseURL     string            `json:"base_url"`     // Base API URL
	QueryFormat string            `json:"query_format"` // URL query format
	APIKey      string            `json:"api_key"`      // API key for service
	Headers     map[string]string `json:"headers"`      // Additional headers
	Timeout     int               `json:"timeout"`      // Request timeout in seconds
	RateLimit   int               `json:"rate_limit"`   // Requests per minute
	CacheTTL    int               `json:"cache_ttl"`    // Cache TTL in seconds
	Threshold   float64           `json:"threshold"`    // Threat threshold
	Provider    string            `json:"provider"`     // Provider name (virustotal, abuseipdb, etc.)
	Enabled     bool              `json:"enabled"`      // Enable/disable this checker
	
	// Response parsing
	ResponseFormat  string `json:"response_format"`  // json, xml, text
	ThreatField     string `json:"threat_field"`     // JSON field indicating threat status
	ScoreField      string `json:"score_field"`      // JSON field for threat score
	CategoriesField string `json:"categories_field"` // JSON field for threat categories
}

// ReputationConfig represents reputation checking configuration
type ReputationConfig struct {
	Enabled         bool                 `json:"enabled"`          // Global reputation checking enable/disable
	MinThreatScore  float64              `json:"min_threat_score"` // Minimum score to consider as threat (0.0-1.0)
	CacheResults    bool                 `json:"cache_results"`    // Cache reputation results
	CacheExpiration int                  `json:"cache_expiration"` // Cache expiration in seconds
	CachePrefix     string               `json:"cache_prefix"`     // Redis cache key prefix
	Checkers        []ReputationChecker  `json:"checkers"`         // List of reputation services
}

// ReputationResult represents the result of reputation checking
type ReputationResult struct {
	Target           string                 `json:"target"`           // IP or domain checked
	IsThreat         bool                   `json:"is_threat"`        // Overall threat assessment
	ThreatScore      float64                `json:"threat_score"`     // Aggregated threat score (0.0-1.0)
	
	// Individual checker results
	CheckerResults   map[string]interface{} `json:"checker_results"`  // Results from each checker
	
	// Aggregated information
	Categories       []string               `json:"categories"`       // Threat categories from all checkers
	Sources          []string               `json:"sources"`          // Which checkers flagged as threat
	
	// Metadata
	CheckedAt        time.Time              `json:"checked_at"`
	CacheHit         bool                   `json:"cache_hit"`
	ErrorCount       int                    `json:"error_count"`      // Number of checkers that errored
	
	// Error information
	Errors           map[string]string      `json:"errors,omitempty"` // Errors from individual checkers
}

// BlacklistData represents data returned by blacklist API endpoints
type BlacklistData struct {
	IPs     []string `json:"ips"`
	Domains []string `json:"domains"`
}

// APIEndpoint represents a single API endpoint for documentation
type APIEndpoint struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Parameters  string `json:"parameters,omitempty"`
	Example     string `json:"example,omitempty"`
}

// APIDocumentation represents the complete API documentation
type APIDocumentation struct {
	Title       string        `json:"title"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	BaseURL     string        `json:"base_url"`
	Endpoints   []APIEndpoint `json:"endpoints"`
}

// HealthStatus represents system health information
type HealthStatus struct {
	Status       string                 `json:"status"` // ok, warning, error
	Uptime       string                 `json:"uptime"`
	RedisStatus  string                 `json:"redis_status"`
	Checks       map[string]interface{} `json:"checks"`
	LastUpdated  time.Time              `json:"last_updated"`
}

// WebUIAuthConfig represents Web UI authentication configuration
type WebUIAuthConfig struct {
	// HTTPS Configuration
	HTTPSEnabled  bool   `json:"https_enabled"`   // Enable HTTPS
	CertFile      string `json:"cert_file"`       // Path to TLS certificate file
	KeyFile       string `json:"key_file"`        // Path to TLS private key file
	
	// Password Authentication
	PasswordAuth  bool   `json:"password_auth"`   // Enable password authentication
	Username      string `json:"username"`        // Username for basic auth
	Password      string `json:"password"`        // Password for basic auth (hashed)
	
	// LDAP Authentication
	LDAPAuth      bool   `json:"ldap_auth"`       // Enable LDAP authentication
	LDAPServer    string `json:"ldap_server"`     // LDAP server URL
	LDAPPort      int    `json:"ldap_port"`       // LDAP server port
	LDAPBaseDN    string `json:"ldap_base_dn"`    // LDAP base DN
	LDAPBindDN    string `json:"ldap_bind_dn"`    // LDAP bind DN
	LDAPBindPass  string `json:"ldap_bind_pass"`  // LDAP bind password
	LDAPUserAttr  string `json:"ldap_user_attr"`  // User attribute (default: uid)
	LDAPSearchFilter string `json:"ldap_search_filter"` // LDAP search filter
	
	// Header Authentication
	HeaderAuth    bool     `json:"header_auth"`     // Enable header authentication
	HeaderName    string   `json:"header_name"`     // Header name to check
	HeaderValues  []string `json:"header_values"`   // Valid header values
	TrustedProxies []string `json:"trusted_proxies"` // Trusted proxy IPs
	
	// Session Configuration
	SessionSecret string `json:"session_secret"`  // Secret for session signing
	SessionExpiry int    `json:"session_expiry"`  // Session expiry in hours
}

// Log Collection Configuration

// LogCollectorConfig represents log collection configuration
type LogCollectorConfig struct {
	Enabled          bool               `json:"enabled"`           // Global log collection enable/disable
	Sources          []LogSource        `json:"sources"`           // List of log sources to monitor
	DefaultTTL       int                `json:"default_ttl"`       // Default TTL for extracted IPs/domains (seconds)
	BufferSize       int                `json:"buffer_size"`       // Line buffer size
	ConnectTimeout   int                `json:"connect_timeout"`   // SSH connection timeout (seconds)
	ReadTimeout      int                `json:"read_timeout"`      // File read timeout (seconds)
	ReconnectDelay   int                `json:"reconnect_delay"`   // Delay before reconnecting on failure (seconds)
	MaxReconnects    int                `json:"max_reconnects"`    // Maximum reconnection attempts (-1 for unlimited)
}

// LogSource represents a single log source (local or remote)
type LogSource struct {
	Name             string             `json:"name"`              // Friendly name for this source
	Type             string             `json:"type"`              // "local" or "ssh"
	Host             string             `json:"host,omitempty"`    // SSH hostname (for remote sources)
	Port             int                `json:"port,omitempty"`    // SSH port (default: 22)
	Username         string             `json:"username,omitempty"`// SSH username
	
	// SSH Authentication
	AuthMethod       string             `json:"auth_method"`       // "key", "password", or "key_password"
	PrivateKeyPath   string             `json:"private_key_path,omitempty"` // Path to SSH private key
	PrivateKeyData   string             `json:"private_key_data,omitempty"` // SSH private key content (base64)
	Passphrase       string             `json:"passphrase,omitempty"`       // SSH key passphrase
	Password         string             `json:"password,omitempty"`         // SSH password
	
	// SSH Host Key Verification
	HostKeyVerification string           `json:"host_key_verification,omitempty"` // "strict", "known_hosts", "fingerprint", or "insecure"
	KnownHostsFile      string           `json:"known_hosts_file,omitempty"`       // Path to known_hosts file
	HostKeyFingerprint  string           `json:"host_key_fingerprint,omitempty"`  // Expected SSH host key fingerprint (SHA256)
	HostKeyAlgorithm    string           `json:"host_key_algorithm,omitempty"`    // Expected host key algorithm (ssh-rsa, ssh-ed25519, etc.)
	
	// File Configuration
	FilePath         string             `json:"file_path"`         // Path to log file
	FollowRotation   bool               `json:"follow_rotation"`   // Handle log rotation
	StartFromEnd     bool               `json:"start_from_end"`    // Start tailing from end of file
	
	// Pattern Matching
	Patterns         []ExtractionPattern `json:"patterns"`         // Regex patterns for IP/domain extraction
	
	// Source-specific settings
	TTL              int                `json:"ttl,omitempty"`     // TTL override for this source
	Environment      map[string]string  `json:"environment,omitempty"` // Environment variables for processing
	Enabled          bool               `json:"enabled"`           // Enable/disable this source
}

// ExtractionPattern represents a regex pattern for extracting IPs/domains from log lines
type ExtractionPattern struct {
	Name             string             `json:"name"`              // Pattern name/description
	Regex            string             `json:"regex"`             // Regular expression pattern
	Type             string             `json:"type"`              // "ip", "domain", or "both"
	IPGroup          int                `json:"ip_group,omitempty"`     // Regex group number for IP (default: 1)
	DomainGroup      int                `json:"domain_group,omitempty"` // Regex group number for domain (default: 1)
	ClientIPGroup    int                `json:"client_ip_group,omitempty"` // Optional: extract client IP from same line
	Enabled          bool               `json:"enabled"`           // Enable/disable this pattern
	TestString       string             `json:"test_string,omitempty"` // Test string for pattern validation
}

// LogCollectorStats represents statistics for log collection
type LogCollectorStats struct {
	TotalSources     int                `json:"total_sources"`
	ActiveSources    int                `json:"active_sources"`
	TotalLinesRead   int64              `json:"total_lines_read"`
	IPsExtracted     int64              `json:"ips_extracted"`
	DomainsExtracted int64              `json:"domains_extracted"`
	ErrorCount       int64              `json:"error_count"`
	LastActivity     time.Time          `json:"last_activity"`
	SourceStats      map[string]*SourceStats `json:"source_stats"`
}

// SourceStats represents statistics for a single log source
type SourceStats struct {
	Name             string             `json:"name"`
	Status           string             `json:"status"`            // "connected", "disconnected", "error"
	LinesRead        int64              `json:"lines_read"`
	IPsExtracted     int64              `json:"ips_extracted"`
	DomainsExtracted int64              `json:"domains_extracted"`
	LastLine         string             `json:"last_line,omitempty"`
	LastActivity     time.Time          `json:"last_activity"`
	ErrorCount       int64              `json:"error_count"`
	LastError        string             `json:"last_error,omitempty"`
	ConnectedAt      time.Time          `json:"connected_at,omitempty"`
	ReconnectCount   int                `json:"reconnect_count"`
}

// LogEntry represents a processed log entry with extracted data
type LogEntry struct {
	Source           string             `json:"source"`            // Source name
	OriginalLine     string             `json:"original_line"`     // Original log line
	Timestamp        time.Time          `json:"timestamp"`         // Entry timestamp
	ExtractedIPs     []string           `json:"extracted_ips"`     // Extracted IP addresses
	ExtractedDomains []string           `json:"extracted_domains"` // Extracted domain names
	ClientIP         string             `json:"client_ip,omitempty"` // Client IP if extracted
	PatternMatched   string             `json:"pattern_matched"`   // Which pattern matched
	ProcessedAt      time.Time          `json:"processed_at"`      // When dfirewall processed this entry
}

// UpstreamClientConfig represents per-client upstream resolver configuration
type UpstreamClientConfig struct {
	// Pattern for matching client IPs (supports CIDR notation, single IPs, or regex patterns)
	ClientPattern string `json:"client_pattern"`
	// Upstream DNS resolver for matching clients (e.g., "1.1.1.1:53")
	Upstream string `json:"upstream"`
	// Description for documentation purposes
	Description string `json:"description,omitempty"`
}

// UpstreamZoneConfig represents per-zone upstream resolver configuration
type UpstreamZoneConfig struct {
	// Zone/domain pattern to match (supports exact domains, wildcards like *.example.com, or regex)
	ZonePattern string `json:"zone_pattern"`
	// Upstream DNS resolver for matching zones (e.g., "8.8.8.8:53")
	Upstream string `json:"upstream"`
	// Description for documentation purposes
	Description string `json:"description,omitempty"`
}

// UpstreamConfig represents the complete upstream resolver configuration
type UpstreamConfig struct {
	// Default upstream resolver (fallback when no specific rules match)
	DefaultUpstream string `json:"default_upstream"`
	// Per-client upstream resolver configurations
	ClientConfigs []UpstreamClientConfig `json:"client_configs,omitempty"`
	// Per-zone upstream resolver configurations
	ZoneConfigs []UpstreamZoneConfig `json:"zone_configs,omitempty"`
	// Priority order: client-specific rules take precedence over zone-specific rules
	// which take precedence over default upstream
}

// ConfigStatus represents configuration status information
type ConfigStatus struct {
	ScriptConfig       *ScriptConfiguration `json:"script_config,omitempty"`
	BlacklistConfig    *BlacklistConfig     `json:"blacklist_config,omitempty"`
	ReputationConfig   *ReputationConfig    `json:"reputation_config,omitempty"`
	AIConfig           *AIConfig            `json:"ai_config,omitempty"`
	CustomScriptConfig *CustomScriptConfig  `json:"custom_script_config,omitempty"`
	WebUIAuthConfig    *WebUIAuthConfig     `json:"webui_auth_config,omitempty"`
	LogCollectorConfig *LogCollectorConfig  `json:"log_collector_config,omitempty"`
	UpstreamConfig     *UpstreamConfig      `json:"upstream_config,omitempty"`
	Environment        map[string]string    `json:"environment"`
	SNIInspectionConfig *SNIInspectionConfig `json:"sni_inspection_config,omitempty"`
	LoadedAt           time.Time            `json:"loaded_at"`
}

// SNI Inspection Configuration

// SNIInspectionConfig represents SNI (Server Name Indication) inspection configuration
type SNIInspectionConfig struct {
	Enabled        bool                      `json:"enabled"`         // Global SNI inspection enable/disable
	ProxyIPs       []string                  `json:"proxy_ips"`       // IP addresses to return instead of real resolved IPs
	ProxyPorts     []int                     `json:"proxy_ports"`     // Ports to listen on for SNI interception
	
	// TLS Configuration
	CertFile       string                    `json:"cert_file"`       // Path to TLS certificate for proxy
	KeyFile        string                    `json:"key_file"`        // Path to TLS private key for proxy
	
	// Timeout and Connection Settings
	ConnectionTimeout int                    `json:"connection_timeout"` // Connection timeout in seconds
	HandshakeTimeout  int                    `json:"handshake_timeout"`  // TLS handshake timeout in seconds
	IdleTimeout      int                     `json:"idle_timeout"`       // Idle connection timeout in seconds
	MaxConnections   int                     `json:"max_connections"`    // Maximum concurrent connections
	
	// Per-client and per-domain configurations
	ClientConfigs    []SNIClientConfig       `json:"client_configs"`     // Client-specific SNI inspection rules
	DomainConfigs    []SNIDomainConfig       `json:"domain_configs"`     // Domain-specific SNI inspection rules
	
	// Validation Settings
	StrictValidation bool                    `json:"strict_validation"`  // Strict SNI validation (block mismatches)
	LogOnly         bool                     `json:"log_only"`          // Only log SNI mismatches, don't block
	
	// Upstream Connection Settings (for valid SNI matches)
	UpstreamTimeout int                      `json:"upstream_timeout"`   // Upstream connection timeout in seconds
	BufferSize      int                      `json:"buffer_size"`        // Buffer size for proxying data
	
	// Statistics and Monitoring
	EnableStats     bool                     `json:"enable_stats"`       // Enable SNI inspection statistics
	StatsRetention  int                      `json:"stats_retention"`    // Statistics retention period in hours
}

// SNIClientConfig represents per-client SNI inspection configuration
type SNIClientConfig struct {
	ClientPattern   string   `json:"client_pattern"`   // Pattern for matching client IPs (CIDR, exact, or regex)
	Enabled         bool     `json:"enabled"`          // Enable SNI inspection for this client
	ProxyIP         string   `json:"proxy_ip"`         // Override proxy IP for this client
	Description     string   `json:"description,omitempty"` // Description for documentation
}

// SNIDomainConfig represents per-domain SNI inspection configuration  
type SNIDomainConfig struct {
	DomainPattern   string   `json:"domain_pattern"`   // Pattern for matching domains (exact, wildcard, or regex)
	Enabled         bool     `json:"enabled"`          // Enable SNI inspection for this domain
	ProxyIP         string   `json:"proxy_ip"`         // Override proxy IP for this domain
	Description     string   `json:"description,omitempty"` // Description for documentation
}

// SNIConnection represents an active SNI inspection connection
type SNIConnection struct {
	ConnectionID    string    `json:"connection_id"`    // Unique connection identifier
	ClientIP        string    `json:"client_ip"`        // Client IP address
	ProxyPort       int       `json:"proxy_port"`       // Port client connected to
	RequestedDomain string    `json:"requested_domain"` // Domain from original DNS request
	SNIDomain       string    `json:"sni_domain"`       // Domain from SNI header
	IsValid         bool      `json:"is_valid"`         // Whether SNI matches requested domain
	StartTime       time.Time `json:"start_time"`       // Connection start time
	LastActivity    time.Time `json:"last_activity"`    // Last activity timestamp
	BytesUpstream   int64     `json:"bytes_upstream"`   // Bytes sent to upstream server
	BytesDownstream int64     `json:"bytes_downstream"` // Bytes sent back to client
	Status          string    `json:"status"`           // Connection status (connecting, active, blocked, closed)
}

// SNIInspectionStats represents SNI inspection statistics
type SNIInspectionStats struct {
	TotalConnections    int64                    `json:"total_connections"`     // Total connections processed
	ValidConnections    int64                    `json:"valid_connections"`     // Connections with valid SNI
	InvalidConnections  int64                    `json:"invalid_connections"`   // Connections with invalid SNI
	BlockedConnections  int64                    `json:"blocked_connections"`   // Connections blocked due to SNI mismatch
	ActiveConnections   int                      `json:"active_connections"`    // Currently active connections
	
	// Per-client statistics
	ClientStats        map[string]*ClientSNIStats `json:"client_stats"`         // Statistics by client IP
	
	// Per-domain statistics
	DomainStats        map[string]*DomainSNIStats `json:"domain_stats"`         // Statistics by domain
	
	// Temporal statistics
	LastHourConnections int64                     `json:"last_hour_connections"` // Connections in last hour
	Last24HourConnections int64                   `json:"last_24h_connections"`   // Connections in last 24 hours
	
	// Error statistics
	TLSErrors          int64                     `json:"tls_errors"`            // TLS handshake errors
	TimeoutErrors      int64                     `json:"timeout_errors"`        // Connection timeout errors
	
	StartTime          time.Time                 `json:"start_time"`            // When statistics collection started
	LastUpdated        time.Time                 `json:"last_updated"`          // Last statistics update
}

// ClientSNIStats represents SNI statistics for a specific client
type ClientSNIStats struct {
	ClientIP           string    `json:"client_ip"`
	TotalConnections   int64     `json:"total_connections"`
	ValidConnections   int64     `json:"valid_connections"`
	InvalidConnections int64     `json:"invalid_connections"`
	BlockedConnections int64     `json:"blocked_connections"`
	LastConnection     time.Time `json:"last_connection"`
	FirstConnection    time.Time `json:"first_connection"`
}

// DomainSNIStats represents SNI statistics for a specific domain
type DomainSNIStats struct {
	Domain             string    `json:"domain"`
	TotalConnections   int64     `json:"total_connections"`
	ValidConnections   int64     `json:"valid_connections"`
	InvalidConnections int64     `json:"invalid_connections"`
	BlockedConnections int64     `json:"blocked_connections"`
	LastConnection     time.Time `json:"last_connection"`
	FirstConnection    time.Time `json:"first_connection"`
}

// SNIMismatchEvent represents an SNI validation mismatch event
type SNIMismatchEvent struct {
	EventID         string    `json:"event_id"`         // Unique event identifier
	Timestamp       time.Time `json:"timestamp"`        // When the mismatch occurred
	ClientIP        string    `json:"client_ip"`        // Client IP address
	RequestedDomain string    `json:"requested_domain"` // Domain from DNS request
	SNIDomain       string    `json:"sni_domain"`       // Domain from SNI header
	ProxyPort       int       `json:"proxy_port"`       // Port connection was made to
	Action          string    `json:"action"`           // Action taken (logged, blocked)
	ConnectionID    string    `json:"connection_id"`    // Associated connection ID
}