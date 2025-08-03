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

// SSH Log Monitoring Configuration

// SSHLogConfig represents SSH log monitoring configuration
type SSHLogConfig struct {
	Enabled         bool           `json:"enabled"`          // Global SSH log monitoring enable/disable
	Servers         []SSHServer    `json:"servers"`          // List of SSH servers to monitor
	GlobalDefaults  SSHDefaults    `json:"global_defaults"`  // Global default settings
	RetryConfig     SSHRetryConfig `json:"retry_config"`     // Retry and connection resilience settings
}

// SSHServer represents a single SSH server and its log monitoring configuration
type SSHServer struct {
	Name            string            `json:"name"`                      // Friendly name for the server
	Host            string            `json:"host"`                      // SSH hostname or IP
	Port            int               `json:"port"`                      // SSH port (default: 22)
	Username        string            `json:"username"`                  // SSH username
	
	// Authentication settings
	AuthMethod      string            `json:"auth_method"`               // "password", "key", or "agent"
	Password        string            `json:"password,omitempty"`        // Password for password auth
	PrivateKeyPath  string            `json:"private_key_path,omitempty"` // Path to private key file
	PrivateKeyData  string            `json:"private_key_data,omitempty"` // Inline private key data (base64)
	Passphrase      string            `json:"passphrase,omitempty"`      // Passphrase for encrypted keys
	
	// Host validation
	StrictHostKeyChecking bool        `json:"strict_host_key_checking"`  // Validate host keys
	KnownHostsFile       string       `json:"known_hosts_file,omitempty"` // Path to known_hosts file
	HostKeyFingerprint   string       `json:"host_key_fingerprint,omitempty"` // Expected host key fingerprint
	
	// Log monitoring settings
	LogFiles        []SSHLogFile      `json:"log_files"`                 // Log files to monitor on this server
	Environment     map[string]string `json:"environment,omitempty"`     // Environment variables for this server
	Enabled         bool              `json:"enabled"`                   // Enable/disable this server
	
	// Connection settings
	ConnectionTimeout int             `json:"connection_timeout"`        // SSH connection timeout in seconds
	KeepAlive        int              `json:"keep_alive"`                // SSH keep-alive interval in seconds
	MaxRetries       int              `json:"max_retries"`               // Maximum connection retry attempts
}

// SSHLogFile represents a log file to monitor on an SSH server
type SSHLogFile struct {
	Path            string            `json:"path"`                      // Full path to log file on remote server
	Description     string            `json:"description,omitempty"`     // Description of what this log contains
	
	// Pattern matching for IP/domain extraction
	IPRegex         string            `json:"ip_regex"`                  // Regex pattern to extract IPs from log lines
	DomainRegex     string            `json:"domain_regex,omitempty"`    // Regex pattern to extract domains from log lines
	
	// Log file handling
	FollowRotation  bool              `json:"follow_rotation"`           // Handle log rotation (follow renamed files)
	StartFromEnd    bool              `json:"start_from_end"`            // Start tailing from end of file (true) or beginning (false)
	BufferSize      int               `json:"buffer_size"`               // Buffer size for reading log lines
	
	// Filtering
	IncludeFilter   string            `json:"include_filter,omitempty"`  // Only process lines matching this regex
	ExcludeFilter   string            `json:"exclude_filter,omitempty"`  // Skip lines matching this regex
	
	// Processing settings
	MaxLineLength   int               `json:"max_line_length"`           // Maximum line length to process
	ProcessInterval int               `json:"process_interval"`          // Interval between processing cycles in seconds
	
	// Integration settings
	TreatAsClient   bool              `json:"treat_as_client"`           // Treat extracted IPs as client IPs (for firewall rules)
	ClientIPOverride string           `json:"client_ip_override,omitempty"` // Override client IP for firewall rules
	DefaultDomain   string            `json:"default_domain,omitempty"`  // Default domain when none extracted
	DefaultTTL      int               `json:"default_ttl"`               // Default TTL for extracted IPs/domains
	
	Enabled         bool              `json:"enabled"`                   // Enable/disable this log file
}

// SSHDefaults represents global default settings for SSH log monitoring
type SSHDefaults struct {
	Port              int    `json:"port"`                // Default SSH port
	ConnectionTimeout int    `json:"connection_timeout"`  // Default connection timeout
	KeepAlive        int     `json:"keep_alive"`          // Default keep-alive interval
	MaxRetries       int     `json:"max_retries"`         // Default max retries
	AuthMethod       string  `json:"auth_method"`         // Default auth method
	BufferSize       int     `json:"buffer_size"`         // Default buffer size
	MaxLineLength    int     `json:"max_line_length"`     // Default max line length
	ProcessInterval  int     `json:"process_interval"`    // Default process interval
	DefaultTTL       int     `json:"default_ttl"`         // Default TTL
	StrictHostKeyChecking bool `json:"strict_host_key_checking"` // Default host key checking
}

// SSHRetryConfig represents retry and resilience configuration
type SSHRetryConfig struct {
	InitialDelay     int    `json:"initial_delay"`       // Initial retry delay in seconds
	MaxDelay         int    `json:"max_delay"`           // Maximum retry delay in seconds
	BackoffMultiplier float64 `json:"backoff_multiplier"` // Backoff multiplier for exponential backoff
	MaxReconnectAttempts int `json:"max_reconnect_attempts"` // Max reconnection attempts before giving up
	ReconnectInterval    int `json:"reconnect_interval"`     // Interval between reconnection attempts
	HealthCheckInterval  int `json:"health_check_interval"`  // Health check interval in seconds
}

// SSHLogEntry represents a processed log entry from SSH monitoring
type SSHLogEntry struct {
	ServerName      string            `json:"server_name"`     // Name of the source server
	LogFile         string            `json:"log_file"`        // Path to the source log file
	Line            string            `json:"line"`            // Original log line
	Timestamp       time.Time         `json:"timestamp"`       // When the line was processed
	
	// Extracted data
	ExtractedIPs    []string          `json:"extracted_ips"`   // IPs extracted from the log line
	ExtractedDomains []string         `json:"extracted_domains"` // Domains extracted from the log line
	
	// Processing metadata
	ClientIP        string            `json:"client_ip"`       // Client IP for firewall rules
	Domain          string            `json:"domain"`          // Domain for firewall rules
	TTL             int               `json:"ttl"`             // TTL for firewall rules
	
	// Integration results
	ProcessedAsRule bool              `json:"processed_as_rule"` // Whether this was processed as a firewall rule
	RedisKeys       []string          `json:"redis_keys"`        // Redis keys created for this entry
	
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// SSHMonitorStatus represents the status of SSH log monitoring
type SSHMonitorStatus struct {
	Enabled         bool                    `json:"enabled"`
	ActiveServers   int                     `json:"active_servers"`
	TotalLogFiles   int                     `json:"total_log_files"`
	ActiveLogFiles  int                     `json:"active_log_files"`
	ServerStatuses  map[string]SSHServerStatus `json:"server_statuses"`
	LastUpdated     time.Time               `json:"last_updated"`
}

// SSHServerStatus represents the status of a single SSH server
type SSHServerStatus struct {
	Name            string    `json:"name"`
	Host            string    `json:"host"`
	Connected       bool      `json:"connected"`
	LastConnected   time.Time `json:"last_connected"`
	LastError       string    `json:"last_error,omitempty"`
	LogFilesActive  int       `json:"log_files_active"`
	LinesProcessed  int64     `json:"lines_processed"`
	IPsExtracted    int64     `json:"ips_extracted"`
	DomainsExtracted int64    `json:"domains_extracted"`
	LastActivity    time.Time `json:"last_activity"`
}

// ConfigStatus represents configuration status information
type ConfigStatus struct {
	ScriptConfig     *ScriptConfiguration `json:"script_config,omitempty"`
	BlacklistConfig  *BlacklistConfig     `json:"blacklist_config,omitempty"`
	ReputationConfig *ReputationConfig    `json:"reputation_config,omitempty"`
	AIConfig         *AIConfig            `json:"ai_config,omitempty"`
	CustomScriptConfig *CustomScriptConfig `json:"custom_script_config,omitempty"`
	WebUIAuthConfig  *WebUIAuthConfig     `json:"webui_auth_config,omitempty"`
	SSHLogConfig     *SSHLogConfig        `json:"ssh_log_config,omitempty"`
	Environment      map[string]string    `json:"environment"`
	LoadedAt         time.Time            `json:"loaded_at"`
}