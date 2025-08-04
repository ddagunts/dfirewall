package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Global variables for configuration
var (
	scriptConfig       *ScriptConfiguration
	blacklistConfig    *BlacklistConfig
	reputationConfig   *ReputationConfig
	aiConfig           *AIConfig
	customScriptConfig *CustomScriptConfig

	// Caches for performance
	ipBlacklist         map[string]bool
	domainBlacklist     map[string]bool
	reputationCache     map[string]*ReputationResult
	aiAnalysisCache     map[string]*AIAnalysisResult
	customScriptCache   map[string]*CustomScriptResult
	trafficPatterns     map[string]*AITrafficPattern

	// HTTP client for reputation checks
	httpClient *http.Client

	// Rate limiters for reputation services
	rateLimiters map[string]*time.Ticker

	// Timestamps for cache management
	lastBlacklistLoad time.Time
)

// Configuration Loading Functions

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

// loadAIConfiguration loads AI features configuration from JSON file
func loadAIConfiguration(configPath string) (*AIConfig, error) {
	// ASSUMPTION: Configuration file must exist and be readable
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("AI configuration file does not exist: %s", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read AI configuration file: %w", err)
	}

	var config AIConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse AI configuration JSON: %w", err)
	}

	// ASSUMPTION: Validate essential configuration fields
	if config.Enabled {
		if config.Provider == "" {
			return nil, fmt.Errorf("AI provider must be specified when AI is enabled")
		}
		
		if config.Provider != "local" && config.APIKey == "" {
			return nil, fmt.Errorf("API key is required for cloud AI providers")
		}
		
		if config.Model == "" {
			// ASSUMPTION: Set default models based on provider
			switch config.Provider {
			case "openai":
				config.Model = "gpt-4"
			case "claude":
				config.Model = "claude-3-sonnet-20240229"
			case "local":
				config.Model = "llama2"
			default:
				return nil, fmt.Errorf("unknown AI provider: %s", config.Provider)
			}
		}
		
		if config.BaseURL == "" {
			// ASSUMPTION: Set default base URLs for known providers
			switch config.Provider {
			case "openai":
				config.BaseURL = "https://api.openai.com/v1"
			case "claude":
				config.BaseURL = "https://api.anthropic.com"
			case "local":
				config.BaseURL = "http://localhost:8000" // Default for local models
			}
		}
		
		// ASSUMPTION: Set reasonable defaults for unspecified values
		if config.Timeout == 0 {
			config.Timeout = 30 // 30 seconds default timeout
		}
		if config.MaxAnalysisDelay == 0 {
			config.MaxAnalysisDelay = 10 // 10 minutes default analysis window
		}
		if config.MinConfidence == 0 {
			config.MinConfidence = 0.7 // 70% confidence threshold
		}
		if config.CacheExpiration == 0 {
			config.CacheExpiration = 3600 // 1 hour default
		}
	}

	log.Printf("Loaded AI configuration: provider=%s, model=%s, features=[domain_analysis=%v, traffic_anomalies=%v, proactive_threat_hunting=%v]",
		config.Provider, config.Model, config.DomainAnalysis, config.TrafficAnomalies, config.ProactiveThreatHunting)
	return &config, nil
}

// loadCustomScriptConfiguration loads custom script configuration from JSON file
func loadCustomScriptConfiguration(configPath string) (*CustomScriptConfig, error) {
	// ASSUMPTION: Configuration file must exist and be readable
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("custom script configuration file does not exist: %s", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom script configuration file: %w", err)
	}

	var config CustomScriptConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse custom script configuration JSON: %w", err)
	}

	// ASSUMPTION: Validate configuration and set defaults
	if config.Enabled {
		// Check if at least one script is specified
		hasScript := config.UnifiedScript != "" || config.DomainScript != "" || config.IPScript != ""
		if !hasScript {
			return nil, fmt.Errorf("at least one script path must be specified when custom scripts are enabled")
		}
		
		// Validate script files exist and are executable
		if config.UnifiedScript != "" {
			if err := validateScriptPath(config.UnifiedScript); err != nil {
				return nil, fmt.Errorf("unified_script validation failed: %w", err)
			}
		}
		if config.DomainScript != "" {
			if err := validateScriptPath(config.DomainScript); err != nil {
				return nil, fmt.Errorf("domain_script validation failed: %w", err)
			}
		}
		if config.IPScript != "" {
			if err := validateScriptPath(config.IPScript); err != nil {
				return nil, fmt.Errorf("ip_script validation failed: %w", err)
			}
		}
		
		// Set defaults for unspecified values
		if config.Timeout == 0 {
			config.Timeout = 10 // 10 seconds default timeout
		}
		if config.RetryAttempts == 0 {
			config.RetryAttempts = 1 // No retries by default
		}
		if config.CacheExpiration == 0 {
			config.CacheExpiration = 300 // 5 minutes cache TTL
		}
		
		// ASSUMPTION: Reasonable timeout limits (1 second to 5 minutes)
		if config.Timeout < 1 || config.Timeout > 300 {
			return nil, fmt.Errorf("timeout must be between 1 and 300 seconds, got: %d", config.Timeout)
		}
		
		// ASSUMPTION: Reasonable retry limits (0 to 5 retries)
		if config.RetryAttempts < 0 || config.RetryAttempts > 5 {
			return nil, fmt.Errorf("retry_attempts must be between 0 and 5, got: %d", config.RetryAttempts)
		}
	}

	log.Printf("Loaded custom script configuration: enabled=%v, unified=%s, domain=%s, ip=%s, timeout=%ds, fail_open=%v",
		config.Enabled, config.UnifiedScript, config.DomainScript, config.IPScript, config.Timeout, config.FailOpen)
	return &config, nil
}

// validateScriptPath validates that a script path exists and is executable
func validateScriptPath(scriptPath string) error {
	// ASSUMPTION: Check if file exists
	info, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("script file does not exist: %s", scriptPath)
	}
	
	// ASSUMPTION: Check if it's a regular file (not directory)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("script path is not a regular file: %s", scriptPath)
	}
	
	// ASSUMPTION: Check if file is executable (Unix permissions)
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("script file is not executable: %s (permissions: %o)", scriptPath, info.Mode().Perm())
	}
	
	return nil
}

// initializeCustomScriptSystem initializes the custom script validation system
func initializeCustomScriptSystem() {
	// ASSUMPTION: Initialize global variables and caches
	if customScriptCache == nil {
		customScriptCache = make(map[string]*CustomScriptResult)
	}
	
	if customScriptConfig != nil && customScriptConfig.Enabled {
		log.Printf("Custom script system initialized")
		if customScriptConfig.UnifiedScript != "" {
			log.Printf("Using unified script: %s", customScriptConfig.UnifiedScript)
		} else {
			log.Printf("Using separate scripts - domain: %s, ip: %s", customScriptConfig.DomainScript, customScriptConfig.IPScript)
		}
		log.Printf("Script settings: timeout=%ds, retries=%d, cache=%v, fail_open=%v",
			customScriptConfig.Timeout, customScriptConfig.RetryAttempts, customScriptConfig.CacheResults, customScriptConfig.FailOpen)
	}
}

// executeCustomScript executes user-provided script for domain/IP validation
func executeCustomScript(target, targetType string) *CustomScriptResult {
	if customScriptConfig == nil || !customScriptConfig.Enabled {
		// Return allow result when custom scripts are disabled
		return &CustomScriptResult{
			Target:       target,
			IsAllowed:    true,
			Reason:       "custom scripts disabled",
			ExitCode:     0,
			ExecutionTime: 0,
			Timestamp:    time.Now(),
			FromCache:    false,
			ScriptPath:   "disabled",
		}
	}

	// ASSUMPTION: Check cache first if caching is enabled
	cacheKey := fmt.Sprintf("custom:%s:%s", targetType, target)
	if customScriptConfig.CacheResults {
		if cached, exists := customScriptCache[cacheKey]; exists {
			// ASSUMPTION: Use configured cache TTL
			if time.Since(cached.Timestamp) < time.Duration(customScriptConfig.CacheExpiration)*time.Second {
				cached.FromCache = true
				return cached
			}
			// Cache expired, remove it
			delete(customScriptCache, cacheKey)
		}
	}

	// ASSUMPTION: Determine which script to use based on target type and configuration
	var scriptPath string
	if customScriptConfig.UnifiedScript != "" {
		// Unified script takes precedence
		scriptPath = customScriptConfig.UnifiedScript
	} else if targetType == "domain" && customScriptConfig.DomainScript != "" {
		scriptPath = customScriptConfig.DomainScript
	} else if targetType == "ip" && customScriptConfig.IPScript != "" {
		scriptPath = customScriptConfig.IPScript
	} else {
		// No appropriate script configured for this target type
		return &CustomScriptResult{
			Target:       target,
			IsAllowed:    customScriptConfig.FailOpen,
			Reason:       fmt.Sprintf("no script configured for target type: %s", targetType),
			ExitCode:     -1,
			ExecutionTime: 0,
			Timestamp:    time.Now(),
			FromCache:    false,
			ScriptPath:   "none",
			Error:        fmt.Sprintf("no script configured for target type: %s", targetType),
		}
	}

	// Execute script with retry logic
	var result *CustomScriptResult
	for attempt := 0; attempt <= customScriptConfig.RetryAttempts; attempt++ {
		if attempt > 0 {
			log.Printf("Custom script retry %d/%d for %s (%s)", attempt, customScriptConfig.RetryAttempts, target, targetType)
		}
		
		result = executeScriptAttempt(scriptPath, target, targetType)
		
		// ASSUMPTION: Retry only on execution errors (exit code -1), not on script decision (exit codes 0-255)
		if result.ExitCode != -1 {
			break // Script executed successfully (whether it returned allow or block)
		}
		
		// QUESTION: Should we add exponential backoff between retries?
		// ASSUMPTION: Simple immediate retry for now
		if attempt < customScriptConfig.RetryAttempts {
			time.Sleep(time.Duration(customScriptConfig.RetryDelay) * time.Second)
		}
	}

	// Cache successful results if configured
	if customScriptConfig.CacheResults && result.ExitCode != -1 {
		customScriptCache[cacheKey] = result
	}

	// Log decisions if configured
	if customScriptConfig.LogResults {
		decision := "ALLOW"
		if !result.IsAllowed {
			decision = "BLOCK"
		}
		log.Printf("CUSTOM SCRIPT %s: %s (%s) -> %s (exit_code: %d, execution_time: %.3fs, script: %s)",
			decision, target, targetType, decision, result.ExitCode, float64(result.ExecutionTime)/1000.0, scriptPath)
	}

	return result
}

// executeScriptAttempt performs a single script execution attempt
func executeScriptAttempt(scriptPath, target, targetType string) *CustomScriptResult {
	startTime := time.Now()
	
	// ASSUMPTION: Pass target and type as command line arguments
	// Script should handle: script.sh <target> <type>
	// where <target> is the domain/IP and <type> is "domain" or "ip"
	cmd := exec.Command(scriptPath, target, targetType)
	
	// ASSUMPTION: Set environment variables for additional context
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("DFIREWALL_TARGET=%s", target),
		fmt.Sprintf("DFIREWALL_TYPE=%s", targetType),
		fmt.Sprintf("DFIREWALL_TIMESTAMP=%d", time.Now().Unix()),
	)
	
	// Add custom environment variables if configured
	if customScriptConfig.Environment != nil {
		for key, value := range customScriptConfig.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}
	
	// Set working directory if configured
	if customScriptConfig.WorkingDirectory != "" {
		cmd.Dir = customScriptConfig.WorkingDirectory
	}
	
	// ASSUMPTION: Capture both stdout and stderr
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// ASSUMPTION: Set timeout to prevent hanging scripts
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(customScriptConfig.Timeout)*time.Second)
	defer cancel()
	
	// Run the command with timeout
	err := cmd.Start()
	if err != nil {
		return &CustomScriptResult{
			Target:       target,
			IsAllowed:    customScriptConfig.FailOpen,
			Reason:       fmt.Sprintf("failed to start script: %v", err),
			ExitCode:     -1,
			ExecutionTime: int(time.Since(startTime).Milliseconds()),
			Timestamp:    time.Now(),
			FromCache:    false,
			ScriptPath:   scriptPath,
			Error:        fmt.Sprintf("failed to start script: %v", err),
		}
	}
	
	// Wait for command completion or timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	
	select {
	case err := <-done:
		executionTime := int(time.Since(startTime).Milliseconds())
		
		// ASSUMPTION: Parse exit code to determine decision
		exitCode := 0
		isAllowed := true
		
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
				// ASSUMPTION: Exit code 0 = allow, any non-zero = block
				if exitCode != 0 {
					isAllowed = false
				}
			} else {
				// Other execution error
				return &CustomScriptResult{
					Target:       target,
					IsAllowed:    customScriptConfig.FailOpen,
					Reason:       fmt.Sprintf("script execution error: %v", err),
					ExitCode:     -1,
					Stdout:       stdout.String(),
					Stderr:       stderr.String(),
					ExecutionTime: executionTime,
					Timestamp:    time.Now(),
					FromCache:    false,
					ScriptPath:   scriptPath,
					Error:        fmt.Sprintf("script execution error: %v", err),
				}
			}
		}
		
		return &CustomScriptResult{
			Target:       target,
			IsAllowed:    isAllowed,
			Reason:       strings.TrimSpace(stdout.String()),
			ExitCode:     exitCode,
			Stdout:       stdout.String(),
			Stderr:       stderr.String(),
			ExecutionTime: executionTime,
			Timestamp:    time.Now(),
			FromCache:    false,
			ScriptPath:   scriptPath,
		}
		
	case <-ctx.Done():
		// Timeout occurred, kill the process
		cmd.Process.Kill()
		return &CustomScriptResult{
			Target:       target,
			IsAllowed:    customScriptConfig.FailOpen,
			Reason:       fmt.Sprintf("script execution timeout after %d seconds", customScriptConfig.Timeout),
			ExitCode:     -1,
			Stdout:       stdout.String(),
			Stderr:       stderr.String(),
			ExecutionTime: customScriptConfig.Timeout * 1000, // Convert to milliseconds
			Timestamp:    time.Now(),
			FromCache:    false,
			ScriptPath:   scriptPath,
			Error:        fmt.Sprintf("script execution timeout after %d seconds", customScriptConfig.Timeout),
		}
	}
}

// initializeAISystem initializes the AI analysis system
func initializeAISystem() {
	// ASSUMPTION: Initialize global variables and caches
	if aiAnalysisCache == nil {
		aiAnalysisCache = make(map[string]*AIAnalysisResult)
	}
	if trafficPatterns == nil {
		trafficPatterns = make(map[string]*AITrafficPattern)
	}
	
	if aiConfig != nil && aiConfig.Enabled {
		log.Printf("AI system initialized with provider: %s, model: %s", aiConfig.Provider, aiConfig.Model)
		log.Printf("AI features enabled: domain_analysis=%v, traffic_anomalies=%v, proactive_threat_hunting=%v",
			aiConfig.DomainAnalysis, aiConfig.TrafficAnomalies, aiConfig.ProactiveThreatHunting)
		
		// Start background processes for AI features
		if aiConfig.TrafficAnomalies {
			go trafficAnomalyDetector()
		}
		if aiConfig.ProactiveThreatHunting {
			go threatHuntingEngine()
		}
	}
}

// analyzeWithAI performs AI-powered analysis of domains, IPs, or traffic patterns
func analyzeWithAI(request *AIAnalysisRequest, redisClient *redis.Client) *AIAnalysisResult {
	if aiConfig == nil || !aiConfig.Enabled {
		// Return neutral result when AI is disabled
		return &AIAnalysisResult{
			RequestID:   generateRequestID(),
			Target:      request.Target,
			ThreatScore: 0.5,
			Confidence:  0.0,
			IsMalicious: false,
			IsAnomaly:   false,
			Reasoning:   "AI analysis disabled",
			Provider:    "disabled",
			Timestamp:   time.Now(),
		}
	}

	startTime := time.Now()
	requestID := generateRequestID()
	
	// ASSUMPTION: Check cache first to avoid duplicate AI requests
	cacheKey := fmt.Sprintf("ai:%s:%s", request.QueryType, request.Target)
	if cached, exists := aiAnalysisCache[cacheKey]; exists {
		// ASSUMPTION: Cache results for configured time to reduce AI API costs
		if time.Since(cached.Timestamp) < time.Duration(aiConfig.CacheExpiration)*time.Second {
			cached.FromCache = true
			return cached
		}
		delete(aiAnalysisCache, cacheKey)
	}

	var result *AIAnalysisResult
	var err error

	// ASSUMPTION: Route analysis to appropriate AI function based on type
	switch request.QueryType {
	case "domain":
		result, err = analyzeDomainWithAI(request.Domain, requestID)
	case "traffic_pattern":
		result, err = analyzeTrafficPatternWithAI(request, requestID)
	case "anomaly":
		result, err = analyzeAnomalyWithAI(request, requestID)
	default:
		err = fmt.Errorf("unknown analysis type: %s", request.QueryType)
	}

	if err != nil {
		log.Printf("AI analysis error for %s (%s): %v", request.Target, request.QueryType, err)
		// Return neutral result on error to avoid blocking legitimate traffic
		return &AIAnalysisResult{
			RequestID:   requestID,
			Target:      request.Target,
			ThreatScore: 0.5,
			Confidence:  0.0,
			IsMalicious: false,
			IsAnomaly:   false,
			Reasoning:   fmt.Sprintf("Analysis error: %v", err),
			Provider:    aiConfig.Provider,
			Timestamp:   time.Now(),
		}
	}

	result.AnalysisTime = int(time.Since(startTime).Milliseconds())
	result.FromCache = false

	// Cache successful results
	aiAnalysisCache[cacheKey] = result

	// QUESTION: Should we also store AI analysis results in Redis for persistence?
	// ASSUMPTION: Store in Redis for historical analysis and sharing between instances
	if redisClient != nil {
		ctx := context.Background()
		resultJSON, _ := json.Marshal(result)
		redisKey := fmt.Sprintf("dfirewall:ai:results:%s", requestID)
		redisClient.Set(ctx, redisKey, resultJSON, 24*time.Hour) // Keep for 24 hours
	}

	return result
}

// analyzeDomainWithAI performs AI-powered domain analysis
func analyzeDomainWithAI(domain, requestID string) (*AIAnalysisResult, error) {
	// ASSUMPTION: Construct domain analysis prompt with cybersecurity context
	prompt := fmt.Sprintf(`Analyze this domain for potential security threats: %s

Please evaluate the domain for:
1. Malware hosting or distribution
2. Phishing attempts
3. Command & control (C2) infrastructure
4. Domain generation algorithm (DGA) patterns
5. Suspicious naming patterns or typosquatting
6. Recent registration or short TTL

Respond with a JSON object containing:
{
  "threat_score": 0.0-1.0 (0=safe, 1=dangerous),
  "confidence": 0.0-1.0,
  "is_malicious": boolean,
  "reasoning": "detailed explanation",
  "categories": ["category1", "category2"],
  "indicators": ["indicator1", "indicator2"],
  "recommendations": ["action1", "action2"]
}`, domain)

	response, err := callAI(prompt)
	if err != nil {
		return nil, err
	}

	// ASSUMPTION: Parse AI response as JSON
	var aiResponse struct {
		ThreatScore     float64  `json:"threat_score"`
		Confidence      float64  `json:"confidence"`
		IsMalicious     bool     `json:"is_malicious"`
		Reasoning       string   `json:"reasoning"`
		Categories      []string `json:"categories"`
		Indicators      []string `json:"indicators"`
		Recommendations []string `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(response), &aiResponse); err != nil {
		// ASSUMPTION: If JSON parsing fails, try to extract key information with text parsing
		return parseAITextResponse(response, domain, requestID, "domain")
	}

	return &AIAnalysisResult{
		RequestID:       requestID,
		Target:          domain,
		ThreatScore:     aiResponse.ThreatScore,
		Confidence:      aiResponse.Confidence,
		IsMalicious:     aiResponse.IsMalicious,
		IsAnomaly:       false,
		Reasoning:       aiResponse.Reasoning,
		Categories:      aiResponse.Categories,
		IOCs:            aiResponse.Indicators,
		Recommendation:  strings.Join(aiResponse.Recommendations, "; "),
		Provider:        aiConfig.Provider,
		Model:           aiConfig.Model,
		Timestamp:       time.Now(),
	}, nil
}

// analyzeTrafficPatternWithAI performs AI-powered traffic pattern analysis
func analyzeTrafficPatternWithAI(request *AIAnalysisRequest, requestID string) (*AIAnalysisResult, error) {
	// ASSUMPTION: Extract traffic pattern data from request context
	contextData, _ := json.Marshal(request.Metadata)
	
	prompt := fmt.Sprintf(`Analyze this DNS traffic pattern for potential security threats:

Client IP: %s
Context: %s

Please evaluate for:
1. C2 beaconing behavior
2. Data exfiltration patterns
3. Malware communication
4. Abnormal DNS tunneling
5. DGA-generated domain usage
6. Suspicious temporal patterns

Respond with a JSON object containing:
{
  "threat_score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "is_anomaly": boolean,
  "reasoning": "detailed explanation",
  "categories": ["category1", "category2"],
  "indicators": ["indicator1", "indicator2"],
  "recommendations": ["action1", "action2"]
}`, request.ClientIP, contextData)

	response, err := callAI(prompt)
	if err != nil {
		return nil, err
	}

	var aiResponse struct {
		ThreatScore     float64  `json:"threat_score"`
		Confidence      float64  `json:"confidence"`
		IsAnomaly       bool     `json:"is_anomaly"`
		Reasoning       string   `json:"reasoning"`
		Categories      []string `json:"categories"`
		Indicators      []string `json:"indicators"`
		Recommendations []string `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(response), &aiResponse); err != nil {
		return parseAITextResponse(response, request.Target, requestID, "traffic_pattern")
	}

	return &AIAnalysisResult{
		RequestID:       requestID,
		Target:          request.Target,
		ThreatScore:     aiResponse.ThreatScore,
		Confidence:      aiResponse.Confidence,
		IsMalicious:     aiResponse.ThreatScore > aiConfig.MinConfidence,
		IsAnomaly:       aiResponse.IsAnomaly,
		Reasoning:       aiResponse.Reasoning,
		Categories:      aiResponse.Categories,
		IOCs:            aiResponse.Indicators,
		Recommendation:  strings.Join(aiResponse.Recommendations, "; "),
		Provider:        aiConfig.Provider,
		Model:           aiConfig.Model,
		Timestamp:       time.Now(),
	}, nil
}

// analyzeAnomalyWithAI performs AI-powered anomaly analysis
func analyzeAnomalyWithAI(request *AIAnalysisRequest, requestID string) (*AIAnalysisResult, error) {
	// ASSUMPTION: Generic anomaly analysis for various types of unusual patterns
	contextStr, _ := json.Marshal(request.Context)
	
	prompt := fmt.Sprintf(`Analyze this network anomaly for potential security implications:

Target: %s
Context: %s
Client: %s

Please evaluate whether this represents:
1. Normal network behavior variation
2. Potential security incident
3. System misconfiguration
4. Attack in progress
5. Data exfiltration attempt
6. Malware activity

Respond with a JSON object containing:
{
  "threat_score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "is_anomaly": boolean,
  "reasoning": "detailed explanation",
  "categories": ["category1", "category2"],
  "indicators": ["indicator1", "indicator2"],
  "recommendations": ["action1", "action2"]
}`, request.Target, contextStr, request.ClientIP)

	response, err := callAI(prompt)
	if err != nil {
		return nil, err
	}

	var aiResponse struct {
		ThreatScore     float64  `json:"threat_score"`
		Confidence      float64  `json:"confidence"`
		IsAnomaly       bool     `json:"is_anomaly"`
		Reasoning       string   `json:"reasoning"`
		Categories      []string `json:"categories"`
		Indicators      []string `json:"indicators"`
		Recommendations []string `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(response), &aiResponse); err != nil {
		return parseAITextResponse(response, request.Target, requestID, "anomaly")
	}

	return &AIAnalysisResult{
		RequestID:       requestID,
		Target:          request.Target,
		ThreatScore:     aiResponse.ThreatScore,
		Confidence:      aiResponse.Confidence,
		IsMalicious:     aiResponse.ThreatScore > aiConfig.MinConfidence,
		IsAnomaly:       aiResponse.IsAnomaly,
		Reasoning:       aiResponse.Reasoning,
		Categories:      aiResponse.Categories,
		IOCs:            aiResponse.Indicators,
		Recommendation:  strings.Join(aiResponse.Recommendations, "; "),
		Provider:        aiConfig.Provider,
		Model:           aiConfig.Model,
		Timestamp:       time.Now(),
	}, nil
}

// AI Helper Functions

// callAI makes API calls to the configured AI provider
func callAI(prompt string) (string, error) {
	if aiConfig == nil || !aiConfig.Enabled {
		return "", fmt.Errorf("AI is not enabled")
	}

	// ASSUMPTION: Different providers have different API formats
	switch aiConfig.Provider {
	case "openai":
		return callOpenAI(prompt)
	case "claude":
		return callClaude(prompt)
	case "local":
		return callLocalAI(prompt)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", aiConfig.Provider)
	}
}

// callOpenAI makes API calls to OpenAI
func callOpenAI(prompt string) (string, error) {
	// ASSUMPTION: Use OpenAI's chat completions API
	requestBody := map[string]interface{}{
		"model": aiConfig.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a cybersecurity expert analyzing network traffic and domains for threats. Always respond with valid JSON when requested.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  1000,
		"temperature": 0.1, // Low temperature for consistent, factual responses
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: time.Duration(aiConfig.Timeout) * time.Second}
	
	req, err := http.NewRequest("POST", aiConfig.BaseURL+"/chat/completions", strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+aiConfig.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if response.Error.Message != "" {
		return "", fmt.Errorf("OpenAI API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	return response.Choices[0].Message.Content, nil
}

// callClaude makes API calls to Anthropic Claude
func callClaude(prompt string) (string, error) {
	// ASSUMPTION: Use Claude's messages API
	requestBody := map[string]interface{}{
		"model":      aiConfig.Model,
		"max_tokens": 1000,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: time.Duration(aiConfig.Timeout) * time.Second}
	
	req, err := http.NewRequest("POST", aiConfig.BaseURL+"/v1/messages", strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", aiConfig.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if response.Error.Message != "" {
		return "", fmt.Errorf("Claude API error: %s", response.Error.Message)
	}

	if len(response.Content) == 0 {
		return "", fmt.Errorf("no response from Claude")
	}

	return response.Content[0].Text, nil
}

// callLocalAI makes API calls to local AI models
func callLocalAI(prompt string) (string, error) {
	// ASSUMPTION: Local AI API follows a simple prompt-response format
	requestBody := map[string]interface{}{
		"model":       aiConfig.Model,
		"prompt":      prompt,
		"max_tokens":  1000,
		"temperature": 0.1,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: time.Duration(aiConfig.Timeout) * time.Second}
	
	req, err := http.NewRequest("POST", aiConfig.BaseURL+"/v1/completions", strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response struct {
		Choices []struct {
			Text string `json:"text"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if response.Error.Message != "" {
		return "", fmt.Errorf("Local AI API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no response from local AI")
	}

	return response.Choices[0].Text, nil
}

// generateRequestID generates a unique request ID for AI analysis
func generateRequestID() string {
	// ASSUMPTION: Use timestamp + random suffix for unique IDs
	return fmt.Sprintf("ai_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}

// parseAITextResponse attempts to parse AI response when JSON parsing fails
func parseAITextResponse(response, target, requestID, analysisType string) (*AIAnalysisResult, error) {
	// ASSUMPTION: Try to extract key information from free-form text response
	result := &AIAnalysisResult{
		RequestID:       requestID,
		Target:          target,
		ThreatScore:     0.5, // Default neutral score
		Confidence:      0.3, // Low confidence for text parsing
		IsMalicious:     false,
		IsAnomaly:       false,
		Reasoning:       response, // Use full response as reasoning
		Categories:      []string{},
		IOCs:            []string{},
		Recommendation:  "",
		Provider:        aiConfig.Provider,
		Model:           aiConfig.Model,
		Timestamp:       time.Now(),
	}

	// QUESTION: Should we implement more sophisticated text parsing?
	// ASSUMPTION: Basic keyword-based threat detection for fallback parsing
	responseLower := strings.ToLower(response)
	
	// Look for threat indicators in the response
	threatenWords := []string{"malicious", "dangerous", "threat", "attack", "malware", "phishing", "suspicious"}
	safeWords := []string{"safe", "legitimate", "normal", "benign", "clean"}
	
	threatCount := 0
	safeCount := 0
	
	for _, word := range threatenWords {
		if strings.Contains(responseLower, word) {
			threatCount++
		}
	}
	
	for _, word := range safeWords {
		if strings.Contains(responseLower, word) {
			safeCount++
		}
	}
	
	// Adjust threat score based on keyword analysis
	if threatCount > safeCount {
		result.ThreatScore = 0.7
		result.IsMalicious = true
		result.Categories = []string{"text_analysis_threat"}
	} else if safeCount > threatCount {
		result.ThreatScore = 0.3
		result.Categories = []string{"text_analysis_safe"}
	}

	return result, nil
}

// AI Background Monitoring Functions

// trafficAnomalyDetector runs in background to detect traffic anomalies
func trafficAnomalyDetector() {
	if aiConfig == nil || !aiConfig.Enabled || !aiConfig.TrafficAnomalies {
		return
	}

	log.Printf("Starting AI traffic anomaly detector")
	
	// ASSUMPTION: Run anomaly detection every analysis window
	ticker := time.NewTicker(time.Duration(aiConfig.MaxAnalysisDelay) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// ASSUMPTION: Analyze traffic patterns for all active clients
		for clientIP, pattern := range trafficPatterns {
			if time.Since(pattern.LastSeen) < time.Duration(aiConfig.MaxAnalysisDelay)*time.Minute {
				// Pattern is recent, analyze it
				request := &AIAnalysisRequest{
					QueryType:    "traffic_pattern",
					Target:       clientIP,
					ClientIP:     clientIP,
					Context:      fmt.Sprintf("pattern analysis for %s", clientIP),
					Metadata:     map[string]string{
						"pattern": fmt.Sprintf("%+v", pattern),
					},
					Timestamp:    time.Now(),
				}

				result := analyzeWithAI(request, nil)
				if result.IsAnomaly && result.Confidence > aiConfig.MinConfidence {
					log.Printf("AI ANOMALY DETECTED: Client %s - %s (confidence: %.2f)", clientIP, result.Reasoning, result.Confidence)
					
					// QUESTION: Should we take automated action on anomalies?
					// ASSUMPTION: Log for now, but could trigger alerts or blocking
					if result.Recommendation != "" {
						log.Printf("AI RECOMMENDATION for %s: %s", clientIP, result.Recommendation)
					}
				}
			}
		}
	}
}

// threatHuntingEngine runs in background for proactive threat hunting
func threatHuntingEngine() {
	if aiConfig == nil || !aiConfig.Enabled || !aiConfig.ProactiveThreatHunting {
		return
	}

	log.Printf("Starting AI threat hunting engine")
	
	// ASSUMPTION: Run threat hunting every 30 minutes
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// ASSUMPTION: Hunt for threats across all recent traffic patterns
		huntThreats()
	}
}

// huntThreats performs proactive threat hunting using AI
func huntThreats() {
	// ASSUMPTION: Collect recent domains and patterns for analysis
	var recentDomains []string
	var suspiciousPatterns []string
	
	for _, pattern := range trafficPatterns {
		if time.Since(pattern.LastSeen) < time.Hour {
			recentDomains = append(recentDomains, pattern.ClientIP)
			
			// ASSUMPTION: Flag patterns with high entropy or request volume
			if pattern.Entropy > 0.7 || pattern.AverageQPS > 30 {
				suspiciousPatterns = append(suspiciousPatterns, fmt.Sprintf("Client %s: entropy=%.2f, qps=%.2f",
					pattern.ClientIP, pattern.Entropy, pattern.AverageQPS))
			}
		}
	}

	if len(recentDomains) == 0 && len(suspiciousPatterns) == 0 {
		return // Nothing to hunt
	}

	// ASSUMPTION: Use AI to analyze collected data for threats
	request := &AIAnalysisRequest{
		QueryType: "threat_hunting",
		Target:    "network_analysis",
		Context:   "proactive threat hunting analysis",
		Metadata: map[string]string{
			"recent_domains":       strings.Join(recentDomains, ","),
			"suspicious_patterns":  strings.Join(suspiciousPatterns, ";"),
			"analysis_time":        time.Now().String(),
		},
		Timestamp: time.Now(),
	}

	result := analyzeWithAI(request, nil)
	if result.ThreatScore > aiConfig.MinConfidence {
		log.Printf("AI THREAT HUNTING ALERT: %s (threat_score: %.2f, confidence: %.2f)", 
			result.Reasoning, result.ThreatScore, result.Confidence)
		
		for _, indicator := range result.IOCs {
			log.Printf("AI THREAT INDICATOR: %s", indicator)
		}
	}
}

// updateTrafficPattern updates traffic patterns for AI analysis
func updateTrafficPattern(clientIP, domain, resolvedIP string) {
	if trafficPatterns == nil {
		trafficPatterns = make(map[string]*AITrafficPattern)
	}

	now := time.Now()
	
	// Get or create traffic pattern for this client
	pattern, exists := trafficPatterns[clientIP]
	if !exists || time.Since(pattern.LastSeen) > time.Duration(aiConfig.MaxAnalysisDelay)*time.Minute {
		// Create new pattern window
		pattern = &AITrafficPattern{
			ClientIP:       clientIP,
			TimeWindow:     fmt.Sprintf("%dm", aiConfig.MaxAnalysisDelay),
			RequestCount:   0,
			UniqueDomains:  0,
			UniqueIPs:      0,
			DomainFrequency: make(map[string]int),
			IPFrequency:     make(map[string]int),
			QueryTypes:      make(map[string]int),
			FirstSeen:       now,
			LastSeen:        now,
			RequestSpacing:  []int{},
		}
		trafficPatterns[clientIP] = pattern
	}

	// Update pattern metrics
	pattern.RequestCount++
	pattern.LastSeen = now

	// Track unique domains
	if pattern.DomainFrequency[domain] == 0 {
		pattern.UniqueDomains++
	}
	pattern.DomainFrequency[domain]++

	// Track unique IPs
	if pattern.IPFrequency[resolvedIP] == 0 {
		pattern.UniqueIPs++
	}
	pattern.IPFrequency[resolvedIP]++

	// Calculate request rate (requests per second)
	windowDuration := time.Since(pattern.FirstSeen).Seconds()
	if windowDuration > 0 {
		pattern.AverageQPS = float64(pattern.RequestCount) / windowDuration
	}

	// ASSUMPTION: Simple beaconing detection based on regularity
	if pattern.RequestCount > 10 && pattern.UniqueDomains < 3 {
		pattern.AnomalyScore = 0.8 // High likelihood of beaconing
	} else if pattern.AverageQPS > 60 { // More than 1 request per second
		pattern.AnomalyScore = 0.6
	} else {
		pattern.AnomalyScore = 0.2
	}

	// ASSUMPTION: Calculate domain name entropy for DGA detection
	pattern.Entropy = calculateDomainEntropy(domain)
}

// calculateDomainEntropy calculates entropy of domain name for DGA detection
func calculateDomainEntropy(domain string) float64 {
	// Remove TLD for analysis
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return 0
	}
	
	subdomain := parts[0]
	if len(subdomain) == 0 {
		return 0
	}
	
	// Count character frequencies
	charCount := make(map[rune]int)
	for _, char := range subdomain {
		charCount[char]++
	}
	
	// Calculate entropy
	entropy := 0.0
	length := float64(len(subdomain))
	
	for _, count := range charCount {
		freq := float64(count) / length
		if freq > 0 {
			entropy -= freq * (float64(count) / length)
		}
	}
	
	return entropy
}

// Reputation checking functions

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
	cacheKey := fmt.Sprintf("dfirewall:reputation:%s:%s", targetType, target)
	
	// Check in-memory cache first
	if cached, exists := reputationCache[cacheKey]; exists {
		// Use default cache TTL of 1 hour (3600 seconds)
		defaultCacheTTL := 3600
		if time.Since(cached.CheckedAt) < time.Duration(defaultCacheTTL)*time.Second {
			cached.CacheHit = true
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
				result.CacheHit = true
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
			result.CacheHit = false
			
			// Cache the result
			if reputationConfig.CacheResults {
				// Cache in memory
				reputationCache[cacheKey] = result
				
				// Cache in Redis if available
				if redisClient != nil {
					ctx := context.Background()
					if data, err := json.Marshal(result); err == nil {
						redisClient.Set(ctx, cacheKey, data, time.Duration(reputationConfig.CacheExpiration)*time.Second)
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
	switch checker.Name {
	case "virustotal":
		return queryVirusTotal(checker, target, targetType)
	case "abuseipdb":
		return queryAbuseIPDB(checker, target, targetType)
	case "urlvoid":
		return queryURLVoid(checker, target, targetType)
	default:
		return queryCustomProvider(checker, target, targetType)
	}
}

// queryVirusTotal queries VirusTotal API
func queryVirusTotal(checker ReputationChecker, target, targetType string) *ReputationResult {
	var apiURL string
	
	if targetType == "ip" {
		apiURL = fmt.Sprintf("%s/ip-address/report?apikey=%s&ip=%s", checker.URL, checker.APIKey, target)
	} else if targetType == "domain" {
		apiURL = fmt.Sprintf("%s/domain/report?apikey=%s&domain=%s", checker.URL, checker.APIKey, target)
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
	isMalicious := score < reputationConfig.MinThreatScore
	
	return &ReputationResult{
		Target:          target,
		IsThreat:        isMalicious,
		ThreatScore:     1.0 - score, // Convert to threat score (higher = more threatening)
		CheckerResults:  map[string]interface{}{"virustotal": vtResponse},
		Categories:      []string{"virustotal"},
		Sources:         []string{"virustotal"},
		CheckedAt:       time.Now(),
		CacheHit:        false,
		ErrorCount:      0,
	}
}

// queryAbuseIPDB queries AbuseIPDB API
func queryAbuseIPDB(checker ReputationChecker, target, targetType string) *ReputationResult {
	if targetType != "ip" {
		return nil // AbuseIPDB only supports IP addresses
	}
	
	apiURL := fmt.Sprintf("%s/check", checker.URL)
	
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
	
	// Convert confidence to threat score
	threatScore := confidence / 100.0
	isMalicious := threatScore > reputationConfig.MinThreatScore
	
	return &ReputationResult{
		Target:          target,
		IsThreat:        isMalicious,
		ThreatScore:     threatScore,
		CheckerResults:  map[string]interface{}{"abuseipdb": abuseResponse},
		Categories:      []string{"abuseipdb"},
		Sources:         []string{"abuseipdb"},
		CheckedAt:       time.Now(),
		CacheHit:        false,
		ErrorCount:      0,
	}
}

// queryURLVoid queries URLVoid API
func queryURLVoid(checker ReputationChecker, target, targetType string) *ReputationResult {
	if targetType != "domain" {
		return nil // URLVoid only supports domains
	}
	
	// URLVoid requires API key in URL path
	apiURL := fmt.Sprintf("%s/%s/host/%s", checker.URL, checker.APIKey, target)
	
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
	// This would need proper implementation based on URLVoid's actual response format
	threatScore := 0.2 // Placeholder score
	isMalicious := threatScore > reputationConfig.MinThreatScore
	
	return &ReputationResult{
		Target:          target,
		IsThreat:        isMalicious,
		ThreatScore:     threatScore,
		CheckerResults:  map[string]interface{}{"urlvoid": urlvoidResponse},
		Categories:      []string{"urlvoid"},
		Sources:         []string{"urlvoid"},
		CheckedAt:       time.Now(),
		CacheHit:        false,
		ErrorCount:      0,
	}
}

// queryCustomProvider queries a custom reputation provider
func queryCustomProvider(checker ReputationChecker, target, targetType string) *ReputationResult {
	// ASSUMPTION: Custom provider uses URL template with {target} placeholder
	apiURL := strings.ReplaceAll(checker.URL, "{target}", url.QueryEscape(target))
	
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
	
	threatScore := 0.5 // Default neutral score
	if s, ok := customResponse["score"].(float64); ok {
		threatScore = s
	}
	
	isMalicious := threatScore > reputationConfig.MinThreatScore
	
	return &ReputationResult{
		Target:          target,
		IsThreat:        isMalicious,
		ThreatScore:     threatScore,
		CheckerResults:  map[string]interface{}{checker.Name: customResponse},
		Categories:      []string{checker.Name},
		Sources:         []string{checker.Name},
		CheckedAt:       time.Now(),
		CacheHit:        false,
		ErrorCount:      0,
	}
}

// Blacklist functions

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
	
	log.Printf("Loaded blacklist configuration: Redis IP key=%s, Redis domain key=%s, IP file=%s, domain file=%s", 
		config.RedisIPKey, config.RedisDomainKey, config.IPBlacklistFile, config.DomainBlacklistFile)
	
	return &config, nil
}

// initializeRedisBlacklistKeys creates Redis sets for blacklists if they don't exist
func initializeRedisBlacklistKeys(redisClient *redis.Client) error {
	if blacklistConfig == nil {
		return nil // No blacklist configuration
	}
	
	ctx := context.Background()
	
	// Initialize IP blacklist set if configured
	if blacklistConfig.RedisIPKey != "" {
		exists, err := redisClient.Exists(ctx, blacklistConfig.RedisIPKey).Result()
		if err != nil {
			return fmt.Errorf("failed to check if Redis IP blacklist key exists: %v", err)
		}
		
		if exists == 0 {
			// Create empty set - Redis will create the key when we add the first member
			// For now, just log that we're ready to use it
			log.Printf("Redis IP blacklist key '%s' ready for use (will be created on first addition)", blacklistConfig.RedisIPKey)
		} else {
			// Count existing entries
			count, err := redisClient.SCard(ctx, blacklistConfig.RedisIPKey).Result()
			if err != nil {
				log.Printf("WARNING: Failed to count existing IP blacklist entries: %v", err)
			} else {
				log.Printf("Redis IP blacklist key '%s' already exists with %d entries", blacklistConfig.RedisIPKey, count)
			}
		}
	}
	
	// Initialize domain blacklist set if configured
	if blacklistConfig.RedisDomainKey != "" {
		exists, err := redisClient.Exists(ctx, blacklistConfig.RedisDomainKey).Result()
		if err != nil {
			return fmt.Errorf("failed to check if Redis domain blacklist key exists: %v", err)
		}
		
		if exists == 0 {
			// Create empty set - Redis will create the key when we add the first member
			log.Printf("Redis domain blacklist key '%s' ready for use (will be created on first addition)", blacklistConfig.RedisDomainKey)
		} else {
			// Count existing entries
			count, err := redisClient.SCard(ctx, blacklistConfig.RedisDomainKey).Result()
			if err != nil {
				log.Printf("WARNING: Failed to count existing domain blacklist entries: %v", err)
			} else {
				log.Printf("Redis domain blacklist key '%s' already exists with %d entries", blacklistConfig.RedisDomainKey, count)
			}
		}
	}
	
	return nil
}

// loadFileBlacklists loads blacklists from files into memory
func loadFileBlacklists() error {
	if blacklistConfig == nil {
		return nil // No blacklist configuration
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
	if blacklistConfig.RedisIPKey != "" && redisClient != nil {
		exists, err := redisClient.SIsMember(ctx, blacklistConfig.RedisIPKey, ip).Result()
		if err != nil {
			log.Printf("WARNING: Failed to check Redis IP blacklist: %v", err)
		} else if exists {
			log.Printf("BLACKLIST HIT: IP %s found in Redis blacklist set %s", ip, blacklistConfig.RedisIPKey)
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
	if blacklistConfig.RedisDomainKey != "" && redisClient != nil {
		exists, err := redisClient.SIsMember(ctx, blacklistConfig.RedisDomainKey, normalizedDomain).Result()
		if err != nil {
			log.Printf("WARNING: Failed to check Redis domain blacklist: %v", err)
		} else if exists {
			log.Printf("BLACKLIST HIT: Domain %s found in Redis blacklist set %s", normalizedDomain, blacklistConfig.RedisDomainKey)
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

// validateForShellExecution validates inputs for safe shell execution
// Returns an error if the input is not safe to pass to a shell command
func validateForShellExecution(input, inputType string) error {
	if input == "" {
		return fmt.Errorf("%s cannot be empty", inputType)
	}
	
	switch inputType {
	case "ip":
		if !validateIPForExecution(input) {
			return fmt.Errorf("invalid IP address: %s", input)
		}
	case "domain":
		if !validateDomainForExecution(input) {
			return fmt.Errorf("invalid domain name: %s", input)
		}
	case "ttl":
		if !validateTTLForExecution(input) {
			return fmt.Errorf("invalid TTL value: %s", input)
		}
	case "action":
		if !validateActionForExecution(input) {
			return fmt.Errorf("invalid action: %s", input)
		}
	default:
		return fmt.Errorf("unknown input type: %s", inputType)
	}
	
	return nil
}

// validateIPForExecution validates IP addresses for shell execution
func validateIPForExecution(ip string) bool {
	// Must be a valid IPv4 or IPv6 address
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	
	// Additional check: must not contain any shell metacharacters
	// Valid IPs should only contain digits, dots, colons, and hex characters (for IPv6)
	for _, char := range ip {
		if !((char >= '0' && char <= '9') || 
			 (char >= 'a' && char <= 'f') || 
			 (char >= 'A' && char <= 'F') || 
			 char == '.' || char == ':') {
			return false
		}
	}
	
	return true
}

// validateDomainForExecution validates domain names for shell execution
func validateDomainForExecution(domain string) bool {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	
	// Basic length checks
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Special case: allow "log:" prefix for log collection entries
	if strings.HasPrefix(domain, "log:") {
		// Validate the part after "log:" as a normal identifier
		logSource := strings.TrimPrefix(domain, "log:")
		if len(logSource) == 0 || len(logSource) > 240 { // Leave room for "log:" prefix
			return false
		}
		// Log source names can contain alphanumeric, hyphens, and underscores
		for _, char := range logSource {
			if !((char >= 'a' && char <= 'z') || 
				 (char >= 'A' && char <= 'Z') || 
				 (char >= '0' && char <= '9') || 
				 char == '-' || char == '_') {
				return false
			}
		}
		return true
	}
	
	// Must not contain shell metacharacters
	// Valid domains should only contain alphanumeric, dots, hyphens, and underscores
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '.' || char == '-' || char == '_') {
			return false
		}
	}
	
	// Additional RFC validation
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		// Cannot start or end with hyphen
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	
	return true
}

// validateTTLForExecution validates TTL values for shell execution
func validateTTLForExecution(ttl string) bool {
	// Must be a valid positive integer
	value, err := strconv.ParseUint(ttl, 10, 32)
	if err != nil {
		return false
	}
	
	// TTL should be reasonable (1 second to 24 hours)
	return value > 0 && value <= 86400
}

// validateActionForExecution validates action strings for shell execution
func validateActionForExecution(action string) bool {
	// Only allow specific predefined actions (case-insensitive)
	allowedActions := map[string]bool{
		"add":    true,
		"remove": true,
		"expire": true,
		"allow":  true,
		"deny":   true,
		"ADD":    true,
		"REMOVE": true,
		"EXPIRE": true,
		"ALLOW":  true,
		"DENY":   true,
	}
	
	return allowedActions[action]
}

// validateInvokeScript validates script paths for security
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

// Redis Key Security Functions

// parseRedisKey safely parses a Redis key and validates components before use
// Returns parsed components and error if invalid
func parseRedisKey(key string) (clientIP, resolvedIP, domain string, err error) {
	// Validate key format
	if !strings.HasPrefix(key, "rules:") {
		return "", "", "", fmt.Errorf("invalid key format: must start with 'rules:'")
	}
	
	// Remove prefix and split
	keyContent := strings.TrimPrefix(key, "rules:")
	parts := strings.Split(keyContent, "|")
	
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid key format: expected 3 parts, got %d", len(parts))
	}
	
	clientIP = parts[0]
	resolvedIP = parts[1] 
	domain = parts[2]
	
	// Validate each component before returning
	if err := validateForShellExecution(clientIP, "ip"); err != nil {
		return "", "", "", fmt.Errorf("invalid client IP in Redis key: %v", err)
	}
	
	if err := validateForShellExecution(resolvedIP, "ip"); err != nil {
		return "", "", "", fmt.Errorf("invalid resolved IP in Redis key: %v", err)
	}
	
	if err := validateForShellExecution(domain, "domain"); err != nil {
		return "", "", "", fmt.Errorf("invalid domain in Redis key: %v", err)
	}
	
	return clientIP, resolvedIP, domain, nil
}

// validateRedisKeyComponents validates Redis key components for API exposure
// This is a more lenient validation for display purposes (not script execution)
func validateRedisKeyComponents(clientIP, resolvedIP, domain string) error {
	// Basic format checks - allow some special cases for log entries
	if clientIP == "" || resolvedIP == "" || domain == "" {
		return fmt.Errorf("Redis key components cannot be empty")
	}
	
	// Check for obvious injection attempts
	dangerousChars := []string{";", "&", "|", "`", "$", "(", ")", "<", ">", "\"", "'", "\\"}
	components := []string{clientIP, resolvedIP, domain}
	names := []string{"clientIP", "resolvedIP", "domain"}
	
	for i, component := range components {
		for _, char := range dangerousChars {
			if strings.Contains(component, char) {
				return fmt.Errorf("potentially malicious character '%s' found in %s: %s", char, names[i], component)
			}
		}
		
		// Length check to prevent buffer overflow attempts
		if len(component) > 253 {
			return fmt.Errorf("%s too long: %d characters (max 253)", names[i], len(component))
		}
	}
	
	return nil
}