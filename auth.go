package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
)

var (
	authConfig     *WebUIAuthConfig
	sessionManager *SessionManager
)

// SessionManager handles user sessions
type SessionManager struct {
	secret   []byte
	expiry   time.Duration
	sessions map[string]*Session
}

type Session struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// loadAuthConfig loads authentication configuration from file or environment
func loadAuthConfig() *WebUIAuthConfig {
	configPath := os.Getenv("WEBUI_AUTH_CONFIG")
	
	config := &WebUIAuthConfig{
		// Default values
		HTTPSEnabled:  false,
		PasswordAuth:  false,
		LDAPAuth:      false,
		HeaderAuth:    false,
		LDAPPort:      389,
		LDAPUserAttr:  "uid",
		SessionExpiry: 24, // 24 hours
	}
	
	// Load from file if specified
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			if err := json.Unmarshal(data, config); err != nil {
				log.Printf("Error parsing auth config: %v", err)
			} else {
				log.Printf("Loaded auth config from: %s", configPath)
			}
		} else {
			log.Printf("Auth config file not found: %s", configPath)
		}
	}
	
	// Override with environment variables
	if os.Getenv("WEBUI_HTTPS_ENABLED") == "true" {
		config.HTTPSEnabled = true
	}
	if certFile := os.Getenv("WEBUI_CERT_FILE"); certFile != "" {
		config.CertFile = certFile
	}
	if keyFile := os.Getenv("WEBUI_KEY_FILE"); keyFile != "" {
		config.KeyFile = keyFile
	}
	
	if os.Getenv("WEBUI_PASSWORD_AUTH") == "true" {
		config.PasswordAuth = true
	}
	if username := os.Getenv("WEBUI_USERNAME"); username != "" {
		config.Username = username
	}
	if password := os.Getenv("WEBUI_PASSWORD"); password != "" {
		// Hash password if it's not already hashed
		if !strings.HasPrefix(password, "$2a$") && !strings.HasPrefix(password, "$2b$") {
			if hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err == nil {
				config.Password = string(hashed)
			} else {
				log.Printf("Error hashing password: %v", err)
			}
		} else {
			config.Password = password
		}
	}
	
	if os.Getenv("WEBUI_LDAP_AUTH") == "true" {
		config.LDAPAuth = true
	}
	if ldapServer := os.Getenv("WEBUI_LDAP_SERVER"); ldapServer != "" {
		config.LDAPServer = ldapServer
	}
	if ldapPort := os.Getenv("WEBUI_LDAP_PORT"); ldapPort != "" {
		if port, err := strconv.Atoi(ldapPort); err == nil {
			config.LDAPPort = port
		}
	}
	if ldapBaseDN := os.Getenv("WEBUI_LDAP_BASE_DN"); ldapBaseDN != "" {
		config.LDAPBaseDN = ldapBaseDN
	}
	if ldapBindDN := os.Getenv("WEBUI_LDAP_BIND_DN"); ldapBindDN != "" {
		config.LDAPBindDN = ldapBindDN
	}
	if ldapBindPass := os.Getenv("WEBUI_LDAP_BIND_PASS"); ldapBindPass != "" {
		config.LDAPBindPass = ldapBindPass
	}
	if ldapUserAttr := os.Getenv("WEBUI_LDAP_USER_ATTR"); ldapUserAttr != "" {
		config.LDAPUserAttr = ldapUserAttr
	}
	if ldapFilter := os.Getenv("WEBUI_LDAP_SEARCH_FILTER"); ldapFilter != "" {
		config.LDAPSearchFilter = ldapFilter
	}
	
	if os.Getenv("WEBUI_HEADER_AUTH") == "true" {
		config.HeaderAuth = true
	}
	if headerName := os.Getenv("WEBUI_HEADER_NAME"); headerName != "" {
		config.HeaderName = headerName
	}
	if headerValues := os.Getenv("WEBUI_HEADER_VALUES"); headerValues != "" {
		config.HeaderValues = strings.Split(headerValues, ",")
		for i := range config.HeaderValues {
			config.HeaderValues[i] = strings.TrimSpace(config.HeaderValues[i])
		}
	}
	if trustedProxies := os.Getenv("WEBUI_TRUSTED_PROXIES"); trustedProxies != "" {
		config.TrustedProxies = strings.Split(trustedProxies, ",")
		for i := range config.TrustedProxies {
			config.TrustedProxies[i] = strings.TrimSpace(config.TrustedProxies[i])
		}
	}
	
	if sessionSecret := os.Getenv("WEBUI_SESSION_SECRET"); sessionSecret != "" {
		config.SessionSecret = sessionSecret
	} else if config.SessionSecret == "" {
		// Generate random session secret
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err == nil {
			config.SessionSecret = base64.StdEncoding.EncodeToString(secret)
		} else {
			log.Printf("Error generating session secret: %v", err)
			config.SessionSecret = "default-insecure-secret"
		}
	}
	
	if sessionExpiry := os.Getenv("WEBUI_SESSION_EXPIRY"); sessionExpiry != "" {
		if expiry, err := strconv.Atoi(sessionExpiry); err == nil {
			config.SessionExpiry = expiry
		}
	}
	
	return config
}

// initAuth initializes the authentication system
func initAuth() {
	authConfig = loadAuthConfig()
	sessionManager = &SessionManager{
		secret:   []byte(authConfig.SessionSecret),
		expiry:   time.Duration(authConfig.SessionExpiry) * time.Hour,
		sessions: make(map[string]*Session),
	}
	
	log.Printf("Auth config loaded - HTTPS: %v, Password: %v, LDAP: %v, Header: %v",
		authConfig.HTTPSEnabled, authConfig.PasswordAuth, authConfig.LDAPAuth, authConfig.HeaderAuth)
}

// isAuthEnabled returns true if any authentication method is enabled
func isAuthEnabled() bool {
	return authConfig != nil && (authConfig.PasswordAuth || authConfig.LDAPAuth || authConfig.HeaderAuth)
}

// authMiddleware handles authentication for protected routes
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthEnabled() {
			next(w, r)
			return
		}
		
		// Check authentication in order of preference
		authenticated := false
		username := ""
		
		// 1. Check header authentication
		if authConfig.HeaderAuth && !authenticated {
			if user, ok := checkHeaderAuth(r); ok {
				authenticated = true
				username = user
			}
		}
		
		// 2. Check session-based authentication (for password/LDAP)
		if !authenticated {
			if user, ok := checkSessionAuth(r); ok {
				authenticated = true
				username = user
			}
		}
		
		if !authenticated {
			// Redirect to login page for browser requests
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			
			// Return 401 for API requests
			w.Header().Set("WWW-Authenticate", `Basic realm="dfirewall"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		
		// Set username in request context for logging and response header
		r.Header.Set("X-Authenticated-User", username)
		w.Header().Set("X-Authenticated-User", username)
		next(w, r)
	}
}

// checkHeaderAuth validates header-based authentication
func checkHeaderAuth(r *http.Request) (string, bool) {
	if !authConfig.HeaderAuth || authConfig.HeaderName == "" {
		return "", false
	}
	
	// Check if request comes from trusted proxy
	clientIP := getClientIP(r)
	if !isTrustedProxy(clientIP) {
		return "", false
	}
	
	headerValue := r.Header.Get(authConfig.HeaderName)
	if headerValue == "" {
		return "", false
	}
	
	// Check if header value is in allowed list
	for _, allowedValue := range authConfig.HeaderValues {
		if headerValue == allowedValue {
			return headerValue, true // Use header value as username
		}
	}
	
	return "", false
}

// checkSessionAuth validates session-based authentication
func checkSessionAuth(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("dfirewall_session")
	if err != nil {
		return "", false
	}
	
	token := cookie.Value
	claims := &Claims{}
	
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return sessionManager.secret, nil
	})
	
	if err != nil || !tkn.Valid {
		return "", false
	}
	
	// Check if session has expired
	if time.Now().After(time.Unix(claims.ExpiresAt, 0)) {
		return "", false
	}
	
	return claims.Username, true
}

// authenticateUser validates username/password against configured auth methods
func authenticateUser(username, password string) bool {
	// Try password authentication first
	if authConfig.PasswordAuth {
		if authConfig.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(authConfig.Password), []byte(password)); err == nil {
				return true
			}
		}
	}
	
	// Try LDAP authentication
	if authConfig.LDAPAuth {
		if authenticateLDAP(username, password) {
			return true
		}
	}
	
	return false
}

// authenticateLDAP validates user credentials against LDAP server
func authenticateLDAP(username, password string) bool {
	if authConfig.LDAPServer == "" {
		return false
	}
	
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", authConfig.LDAPServer, authConfig.LDAPPort))
	if err != nil {
		log.Printf("LDAP connection error: %v", err)
		return false
	}
	defer conn.Close()
	
	// Bind with service account if provided
	if authConfig.LDAPBindDN != "" {
		if err := conn.Bind(authConfig.LDAPBindDN, authConfig.LDAPBindPass); err != nil {
			log.Printf("LDAP bind error: %v", err)
			return false
		}
	}
	
	// Search for user
	searchFilter := fmt.Sprintf("(%s=%s)", authConfig.LDAPUserAttr, username)
	if authConfig.LDAPSearchFilter != "" {
		searchFilter = fmt.Sprintf("(&%s(%s=%s))", authConfig.LDAPSearchFilter, authConfig.LDAPUserAttr, username)
	}
	
	searchRequest := ldap.NewSearchRequest(
		authConfig.LDAPBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn"},
		nil,
	)
	
	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("LDAP search error: %v", err)
		return false
	}
	
	if len(sr.Entries) != 1 {
		log.Printf("LDAP user not found or ambiguous: %s", username)
		return false
	}
	
	userDN := sr.Entries[0].DN
	
	// Authenticate by binding as the user
	if err := conn.Bind(userDN, password); err != nil {
		log.Printf("LDAP authentication failed for user %s: %v", username, err)
		return false
	}
	
	return true
}

// createSession creates a new session for authenticated user
func createSession(username string) (string, error) {
	expirationTime := time.Now().Add(sessionManager.expiry)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(sessionManager.secret)
	if err != nil {
		return "", err
	}
	
	// Store session
	sessionID := generateSessionID()
	sessionManager.sessions[sessionID] = &Session{
		ID:        sessionID,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: expirationTime,
	}
	
	return tokenString, nil
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return fmt.Sprintf("%x", sha256.Sum256(bytes))
}

// getClientIP extracts the real client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Use remote address
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// isTrustedProxy checks if IP is in trusted proxy list
func isTrustedProxy(ip string) bool {
	if len(authConfig.TrustedProxies) == 0 {
		return true // If no trusted proxies configured, trust all
	}
	
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	
	for _, trustedIP := range authConfig.TrustedProxies {
		// Check if it's a CIDR
		if strings.Contains(trustedIP, "/") {
			_, network, err := net.ParseCIDR(trustedIP)
			if err == nil && network.Contains(clientIP) {
				return true
			}
		} else {
			// Direct IP comparison
			if ip == trustedIP {
				return true
			}
		}
	}
	
	return false
}

// handleLogin handles the login page and authentication
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Serve login page
		loginHTML := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>dfirewall - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
        button { width: 100%; padding: 12px; background: #007acc; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #005fa3; }
        .error { color: #dc3545; margin-top: 10px; text-align: center; }
        .info { color: #666; text-align: center; margin-top: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔒 dfirewall</h1>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            <div class="error" id="error" style="display: none;"></div>
        </form>
        <div class="info">Enter your credentials to access the firewall management interface.</div>
    </div>
</body>
</html>`
		
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(loginHTML))
		return
	}
	
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		if authenticateUser(username, password) {
			// Create session
			tokenString, err := createSession(username)
			if err != nil {
				http.Error(w, "Error creating session", http.StatusInternalServerError)
				return
			}
			
			// Set session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "dfirewall_session",
				Value:    tokenString,
				Expires:  time.Now().Add(sessionManager.expiry),
				HttpOnly: true,
				Secure:   authConfig.HTTPSEnabled,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
			
			log.Printf("User %s authenticated successfully from %s", username, getClientIP(r))
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		
		log.Printf("Authentication failed for user %s from %s", username, getClientIP(r))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleLogout handles user logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "dfirewall_session",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   authConfig.HTTPSEnabled,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	
	// Remove from session manager
	if cookie, err := r.Cookie("dfirewall_session"); err == nil {
		token := cookie.Value
		claims := &Claims{}
		if tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return sessionManager.secret, nil
		}); err == nil && tkn.Valid {
			// Find and remove session
			for id, session := range sessionManager.sessions {
				if session.Username == claims.Username {
					delete(sessionManager.sessions, id)
					break
				}
			}
		}
	}
	
	http.Redirect(w, r, "/login", http.StatusFound)
}

// cleanupExpiredSessions removes expired sessions
func cleanupExpiredSessions() {
	now := time.Now()
	for id, session := range sessionManager.sessions {
		if now.After(session.ExpiresAt) {
			delete(sessionManager.sessions, id)
		}
	}
}

// periodicSessionCleanup runs session cleanup periodically
func periodicSessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()
}