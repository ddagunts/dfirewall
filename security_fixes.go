package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// SecureSanitizer provides secure input validation and sanitization
type SecureSanitizer struct{}

// validateAndEscapeInput provides secure input validation for different input types
func (s *SecureSanitizer) validateAndEscapeInput(input string, inputType string) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("empty input not allowed")
	}

	// Prevent excessively long inputs
	if len(input) > 1024 {
		return "", fmt.Errorf("input too long: %d bytes", len(input))
	}

	// Check for null bytes and control characters
	for _, r := range input {
		if r == 0 || (r < 32 && r != 9 && r != 10 && r != 13) {
			return "", fmt.Errorf("invalid control character in input")
		}
	}

	switch inputType {
	case "ip":
		return s.validateIP(input)
	case "domain":
		return s.validateDomain(input)
	case "ttl":
		return s.validateTTL(input)
	case "action":
		return s.validateAction(input)
	default:
		return "", fmt.Errorf("unknown input type: %s", inputType)
	}
}

// validateIP validates and normalizes IP addresses
func (s *SecureSanitizer) validateIP(input string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(input))
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", input)
	}

	// Normalize IP representation
	if ip.To4() != nil {
		return ip.To4().String(), nil
	}
	return ip.To16().String(), nil
}

// validateDomain validates domain names according to RFC standards
func (s *SecureSanitizer) validateDomain(input string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(input))
	
	// Length checks
	if len(domain) == 0 {
		return "", fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return "", fmt.Errorf("domain too long: %d characters", len(domain))
	}

	// Check for dangerous patterns
	if strings.Contains(domain, "..") {
		return "", fmt.Errorf("domain contains path traversal sequence")
	}

	// RFC 1035 compliance check
	regex := regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.?$`)
	if !regex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format: %s", input)
	}

	// Check each label
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid label length in domain: %s", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("label cannot start or end with hyphen: %s", label)
		}
	}

	return domain, nil
}

// validateTTL validates TTL values
func (s *SecureSanitizer) validateTTL(input string) (string, error) {
	ttl, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return "", fmt.Errorf("invalid TTL format: %s", input)
	}

	// TTL should be between 0 and 7 days (604800 seconds)
	if ttl < 0 || ttl > 604800 {
		return "", fmt.Errorf("TTL out of range: %d", ttl)
	}

	return strconv.Itoa(ttl), nil
}

// validateAction validates action strings
func (s *SecureSanitizer) validateAction(input string) (string, error) {
	action := strings.ToUpper(strings.TrimSpace(input))
	
	allowedActions := map[string]bool{
		"ALLOW": true,
		"DENY":  true,
		"BLOCK": true,
		"LOG":   true,
	}

	if !allowedActions[action] {
		return "", fmt.Errorf("invalid action: %s", input)
	}

	return action, nil
}

// SecureAuthenticator provides secure authentication mechanisms
type SecureAuthenticator struct {
	mu                sync.RWMutex
	sessions         map[string]*SecureSession
	rateLimiter      *RateLimiter
	trustedProxies   []*net.IPNet
}

// SecureSession represents a secure user session
type SecureSession struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	CSRFToken string
}

// NewSecureAuthenticator creates a new secure authenticator
func NewSecureAuthenticator() *SecureAuthenticator {
	return &SecureAuthenticator{
		sessions:    make(map[string]*SecureSession),
		rateLimiter: NewRateLimiter(100, time.Hour), // 100 requests per hour per IP
		trustedProxies: parseTrustedProxies(),
	}
}

// parseTrustedProxies parses trusted proxy CIDRs from configuration
func parseTrustedProxies() []*net.IPNet {
	var proxies []*net.IPNet
	
	// Default trusted proxies (localhost)
	defaultProxies := []string{"127.0.0.0/8", "::1/128"}
	
	// Add configured proxies if available
	if authConfig != nil && len(authConfig.TrustedProxies) > 0 {
		defaultProxies = append(defaultProxies, authConfig.TrustedProxies...)
	}
	
	for _, cidr := range defaultProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			proxies = append(proxies, ipNet)
		}
	}
	
	return proxies
}

// generateSecureSessionID generates a cryptographically secure session ID
func (sa *SecureAuthenticator) generateSecureSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// CreateSession creates a new secure session
func (sa *SecureAuthenticator) CreateSession(userID, ipAddress, userAgent string) (*SecureSession, error) {
	sessionID, err := sa.generateSecureSessionID()
	if err != nil {
		return nil, err
	}

	csrfToken, err := sa.generateSecureSessionID()
	if err != nil {
		return nil, err
	}

	session := &SecureSession{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(authConfig.SessionExpiry) * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CSRFToken: csrfToken,
	}

	sa.mu.Lock()
	sa.sessions[sessionID] = session
	sa.mu.Unlock()

	return session, nil
}

// ValidateSession validates a session and returns user info if valid
func (sa *SecureAuthenticator) ValidateSession(sessionID, ipAddress, userAgent string) (*SecureSession, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("empty session ID")
	}

	sa.mu.RLock()
	session, exists := sa.sessions[sessionID]
	sa.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		sa.InvalidateSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Optional: Check IP consistency (can be disabled for mobile users)
	if session.IPAddress != ipAddress {
		// Log potential session hijacking attempt
		secureLog("WARN", "Session IP mismatch", map[string]interface{}{
			"session_id": sessionID,
			"original_ip": session.IPAddress,
			"current_ip": ipAddress,
		})
	}

	return session, nil
}

// InvalidateSession removes a session
func (sa *SecureAuthenticator) InvalidateSession(sessionID string) {
	sa.mu.Lock()
	delete(sa.sessions, sessionID)
	sa.mu.Unlock()
}

// CleanupExpiredSessions removes expired sessions
func (sa *SecureAuthenticator) CleanupExpiredSessions() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	now := time.Now()
	for sessionID, session := range sa.sessions {
		if now.After(session.ExpiresAt) {
			delete(sa.sessions, sessionID)
		}
	}
}

// CheckHeaderAuth securely validates header-based authentication
func (sa *SecureAuthenticator) CheckHeaderAuth(r *http.Request) bool {
	if authConfig == nil || !authConfig.HeaderAuth {
		return false
	}

	// Rate limiting
	clientIP := getClientIP(r)
	if !sa.rateLimiter.Allow(clientIP) {
		secureLog("WARN", "Rate limit exceeded for header auth", map[string]interface{}{
			"client_ip": clientIP,
		})
		return false
	}

	// Validate request comes from trusted proxy
	if !sa.isTrustedProxy(clientIP) {
		secureLog("WARN", "Header auth from untrusted proxy", map[string]interface{}{
			"client_ip": clientIP,
		})
		return false
	}

	// Get and validate header value
	headerValue := r.Header.Get(authConfig.HeaderName)
	if headerValue == "" {
		return false
	}

	// Check against allowed values with constant-time comparison
	for _, validValue := range authConfig.HeaderValues {
		if subtle.ConstantTimeCompare([]byte(headerValue), []byte(validValue)) == 1 {
			secureLog("INFO", "Successful header authentication", map[string]interface{}{
				"client_ip": clientIP,
				"header": authConfig.HeaderName,
			})
			return true
		}
	}

	secureLog("WARN", "Failed header authentication", map[string]interface{}{
		"client_ip": clientIP,
		"header": authConfig.HeaderName,
		"provided_value": "[REDACTED]",
	})
	return false
}

// isTrustedProxy checks if an IP is from a trusted proxy
func (sa *SecureAuthenticator) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, trusted := range sa.trustedProxies {
		if trusted.Contains(ip) {
			return true
		}
	}
	return false
}

// Note: getClientIP function is already defined in auth.go

// SecureLDAPAuth provides secure LDAP authentication
func SecureLDAPAuth(username, password string) bool {
	if authConfig == nil || !authConfig.LDAPAuth {
		return false
	}

	// Input validation
	if len(username) == 0 || len(password) == 0 {
		return false
	}

	// Prevent excessively long inputs
	if len(username) > 256 || len(password) > 256 {
		secureLog("WARN", "LDAP auth attempt with oversized input", map[string]interface{}{
			"username_length": len(username),
			"password_length": len(password),
		})
		return false
	}

	// Connect to LDAP server with timeout
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", authConfig.LDAPServer, authConfig.LDAPPort))
	if err != nil {
		secureLog("ERROR", "LDAP connection failed", map[string]interface{}{
			"server": authConfig.LDAPServer,
			"error": err.Error(),
		})
		return false
	}
	defer conn.Close()

	// Set connection timeout
	conn.SetTimeout(10 * time.Second)

	// Bind with service account
	err = conn.Bind(authConfig.LDAPBindDN, authConfig.LDAPBindPass)
	if err != nil {
		secureLog("ERROR", "LDAP bind failed", map[string]interface{}{
			"bind_dn": authConfig.LDAPBindDN,
			"error": err.Error(),
		})
		return false
	}

	// Escape username for LDAP filter - CRITICAL SECURITY FIX
	escapedUsername := ldap.EscapeFilter(username)
	
	// Search for user
	searchFilter := fmt.Sprintf(authConfig.LDAPSearchFilter, escapedUsername)
	searchRequest := ldap.NewSearchRequest(
		authConfig.LDAPBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit
		10, // Time limit (seconds)
		false,
		searchFilter,
		[]string{authConfig.LDAPUserAttr},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		secureLog("ERROR", "LDAP search failed", map[string]interface{}{
			"filter": searchFilter,
			"error": err.Error(),
		})
		return false
	}

	if len(searchResult.Entries) != 1 {
		secureLog("WARN", "LDAP user not found or ambiguous", map[string]interface{}{
			"username": username,
			"results": len(searchResult.Entries),
		})
		return false
	}

	// Attempt to bind as the user
	userDN := searchResult.Entries[0].DN
	err = conn.Bind(userDN, password)
	if err != nil {
		secureLog("WARN", "LDAP authentication failed", map[string]interface{}{
			"username": username,
			"user_dn": userDN,
		})
		return false
	}

	secureLog("INFO", "Successful LDAP authentication", map[string]interface{}{
		"username": username,
		"user_dn": userDN,
	})
	return true
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	
	// Initialize if first request
	if rl.requests[clientIP] == nil {
		rl.requests[clientIP] = []time.Time{now}
		return true
	}

	// Clean expired requests
	var validRequests []time.Time
	for _, reqTime := range rl.requests[clientIP] {
		if now.Sub(reqTime) < rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= rl.limit {
		rl.requests[clientIP] = validRequests
		return false
	}

	// Add current request
	rl.requests[clientIP] = append(validRequests, now)
	return true
}

// secureLog provides secure logging with sensitive data redaction
func secureLog(level string, message string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}

	// Add timestamp
	fields["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	// Sanitize fields to prevent log injection and redact sensitive data
	sanitizedFields := make(map[string]interface{})
	for k, v := range fields {
		key := strings.ToLower(k)
		
		// Redact sensitive data
		if strings.Contains(key, "password") ||
		   strings.Contains(key, "secret") ||
		   strings.Contains(key, "token") ||
		   strings.Contains(key, "key") ||
		   strings.Contains(key, "auth") {
			sanitizedFields[k] = "[REDACTED]"
		} else {
			// Sanitize log values to prevent injection
			sanitizedFields[k] = sanitizeLogValue(v)
		}
	}

	// Use structured logging in production
	fmt.Printf("[%s] %s %+v\n", level, message, sanitizedFields)
}

// sanitizeLogValue sanitizes individual log values
func sanitizeLogValue(value interface{}) interface{} {
	if str, ok := value.(string); ok {
		// Remove newlines and control characters that could break log format
		cleaned := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			if r < 32 || r == 127 {
				return -1 // Remove control characters
			}
			return r
		}, str)
		
		// Truncate very long values
		if len(cleaned) > 1000 {
			return cleaned[:1000] + "...[TRUNCATED]"
		}
		return cleaned
	}
	return value
}

// Global instances for secure components
var (
	secureSanitizer     = &SecureSanitizer{}
	secureAuthenticator = NewSecureAuthenticator()
)

// Start periodic cleanup
func init() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			secureAuthenticator.CleanupExpiredSessions()
		}
	}()
}