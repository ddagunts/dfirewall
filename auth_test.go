package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestLoadAuthConfig(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"WEBUI_AUTH_CONFIG":     os.Getenv("WEBUI_AUTH_CONFIG"),
		"WEBUI_HTTPS_ENABLED":   os.Getenv("WEBUI_HTTPS_ENABLED"),
		"WEBUI_PASSWORD_AUTH":   os.Getenv("WEBUI_PASSWORD_AUTH"),
		"WEBUI_USERNAME":        os.Getenv("WEBUI_USERNAME"),
		"WEBUI_PASSWORD":        os.Getenv("WEBUI_PASSWORD"),
		"WEBUI_SESSION_SECRET":  os.Getenv("WEBUI_SESSION_SECRET"),
		"WEBUI_SESSION_EXPIRY":  os.Getenv("WEBUI_SESSION_EXPIRY"),
	}

	// Clean environment
	for key := range originalVars {
		os.Unsetenv(key)
	}

	// Restore environment after test
	defer func() {
		for key, value := range originalVars {
			if value != "" {
				os.Setenv(key, value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	tests := []struct {
		name        string
		envVars     map[string]string
		expectHTTPS bool
		expectAuth  bool
		expectUser  string
	}{
		{
			name:        "Default configuration",
			envVars:     map[string]string{},
			expectHTTPS: false,
			expectAuth:  false,
			expectUser:  "",
		},
		{
			name: "HTTPS enabled",
			envVars: map[string]string{
				"WEBUI_HTTPS_ENABLED": "true",
			},
			expectHTTPS: true,
			expectAuth:  false,
		},
		{
			name: "Password authentication enabled",
			envVars: map[string]string{
				"WEBUI_PASSWORD_AUTH": "true",
				"WEBUI_USERNAME":      "admin",
				"WEBUI_PASSWORD":      "testpass123",
			},
			expectHTTPS: false,
			expectAuth:  true,
			expectUser:  "admin",
		},
		{
			name: "Custom session expiry",
			envVars: map[string]string{
				"WEBUI_SESSION_EXPIRY": "48",
			},
			expectHTTPS: false,
			expectAuth:  false,
		},
		{
			name: "Custom session secret",
			envVars: map[string]string{
				"WEBUI_SESSION_SECRET": "custom-secret-key",
			},
			expectHTTPS: false,
			expectAuth:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for this test
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			config := loadAuthConfig()

			if config.HTTPSEnabled != tt.expectHTTPS {
				t.Errorf("Expected HTTPS enabled: %v, got: %v", tt.expectHTTPS, config.HTTPSEnabled)
			}

			if config.PasswordAuth != tt.expectAuth {
				t.Errorf("Expected password auth: %v, got: %v", tt.expectAuth, config.PasswordAuth)
			}

			if config.Username != tt.expectUser {
				t.Errorf("Expected username: %s, got: %s", tt.expectUser, config.Username)
			}

			// Check session secret is generated if not provided
			if config.SessionSecret == "" {
				t.Error("Session secret should not be empty")
			}

			// Check password hashing
			if tt.expectAuth && tt.envVars["WEBUI_PASSWORD"] != "" {
				if !strings.HasPrefix(config.Password, "$2a$") && !strings.HasPrefix(config.Password, "$2b$") {
					t.Error("Password should be hashed")
				}
			}

			// Clean up for next test
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestPasswordHashing(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "Simple password",
			password: "password123",
		},
		{
			name:     "Complex password",
			password: "P@ssw0rd!#$%^&*()",
		},
		{
			name:     "Long password",
			password: "ThisIsAVeryLongPasswordThatShouldStillWorkCorrectly123456789",
		},
		{
			name:     "Unicode password",
			password: "пароль123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashed, err := bcrypt.GenerateFromPassword([]byte(tt.password), bcrypt.DefaultCost)
			if err != nil {
				t.Fatalf("Failed to hash password: %v", err)
			}

			// Verify the hash
			err = bcrypt.CompareHashAndPassword(hashed, []byte(tt.password))
			if err != nil {
				t.Errorf("Password verification failed: %v", err)
			}

			// Verify wrong password fails
			err = bcrypt.CompareHashAndPassword(hashed, []byte("wrongpassword"))
			if err == nil {
				t.Error("Wrong password should not verify successfully")
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	// Generate multiple session IDs and check they're unique
	sessionIDs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		
		if len(id) == 0 {
			t.Error("Session ID should not be empty")
		}

		if len(id) != 64 {
			t.Errorf("Expected session ID length 64, got %d", len(id))
		}

		if sessionIDs[id] {
			t.Errorf("Duplicate session ID generated: %s", id)
		}
		sessionIDs[id] = true
	}
}

func TestJWTTokenCreation(t *testing.T) {
	// Initialize session manager for testing
	testSessionManager := &SessionManager{
		secret:   []byte("test-secret-key"),
		expiry:   time.Hour,
		sessions: make(map[string]*Session),
	}

	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "Regular user",
			username: "testuser",
		},
		{
			name:     "Admin user",
			username: "admin",
		},
		{
			name:     "User with special characters",
			username: "user@domain.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original session manager
			originalSM := sessionManager
			sessionManager = testSessionManager

			// Restore after test
			defer func() {
				sessionManager = originalSM
			}()

			tokenString, err := createSession(tt.username)
			if err != nil {
				t.Fatalf("Failed to create session: %v", err)
			}

			if tokenString == "" {
				t.Error("Token string should not be empty")
			}

			// Parse and validate the token
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				return testSessionManager.secret, nil
			})

			if err != nil {
				t.Fatalf("Failed to parse token: %v", err)
			}

			if !token.Valid {
				t.Error("Token should be valid")
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				t.Fatal("Failed to cast token claims")
			}

			if claims.Username != tt.username {
				t.Errorf("Expected username %s, got %s", tt.username, claims.Username)
			}

			if claims.ExpiresAt == nil {
				t.Error("Token should have expiration time")
			}

			if time.Now().After(claims.ExpiresAt.Time) {
				t.Error("Token should not be expired immediately after creation")
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "Direct connection",
			remoteAddr: "192.168.1.100:12345",
			headers:    map[string]string{},
			expectedIP: "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For header",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 10.0.0.1",
			},
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			expectedIP: "203.0.113.2",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			expectedIP: "203.0.113.1",
		},
		{
			name:       "IPv6 remote address",
			remoteAddr: "[2001:db8::1]:12345",
			headers:    map[string]string{},
			expectedIP: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			clientIP := getClientIP(req)
			if clientIP != tt.expectedIP {
				t.Errorf("Expected client IP %s, got %s", tt.expectedIP, clientIP)
			}
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	// Initialize auth config for testing
	testAuthConfig := &WebUIAuthConfig{
		TrustedProxies: []string{
			"127.0.0.1",
			"192.168.1.0/24",
			"10.0.0.1",
			"2001:db8::/32",
		},
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Localhost",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "IP in CIDR range",
			ip:       "192.168.1.50",
			expected: true,
		},
		{
			name:     "Specific trusted IP",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "IPv6 in trusted range",
			ip:       "2001:db8::1",
			expected: true,
		},
		{
			name:     "Untrusted IP",
			ip:       "203.0.113.1",
			expected: false,
		},
		{
			name:     "IP outside CIDR range",
			ip:       "192.168.2.1",
			expected: false,
		},
		{
			name:     "Invalid IP",
			ip:       "not-an-ip",
			expected: false,
		},
	}

	// Save original auth config
	originalAuthConfig := authConfig
	authConfig = testAuthConfig

	// Restore after test
	defer func() {
		authConfig = originalAuthConfig
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTrustedProxy(tt.ip)
			if result != tt.expected {
				t.Errorf("isTrustedProxy(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	// Initialize test auth config
	testAuthConfig := &WebUIAuthConfig{
		PasswordAuth:   true,
		Username:       "admin",
		Password:       "$2a$10$test.hash.for.testing",
		SessionSecret:  "test-secret",
		SessionExpiry:  24,
	}

	testSessionManager := &SessionManager{
		secret:   []byte("test-secret"),
		expiry:   24 * time.Hour,
		sessions: make(map[string]*Session),
	}

	// Save original values
	originalAuthConfig := authConfig
	originalSessionManager := sessionManager

	authConfig = testAuthConfig
	sessionManager = testSessionManager

	// Restore after test
	defer func() {
		authConfig = originalAuthConfig
		sessionManager = originalSessionManager
	}()

	tests := []struct {
		name           string
		authEnabled    bool
		validToken     bool
		expectedStatus int
		expectRedirect bool
	}{
		{
			name:           "No auth required",
			authEnabled:    false,
			validToken:     false,
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
		{
			name:           "Valid token",
			authEnabled:    true,
			validToken:     true,
			expectedStatus: http.StatusOK,
			expectRedirect: false,
		},
		{
			name:           "No token - browser request",
			authEnabled:    true,
			validToken:     false,
			expectedStatus: http.StatusFound,
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Temporarily disable auth if needed
			if !tt.authEnabled {
				authConfig.PasswordAuth = false
			} else {
				authConfig.PasswordAuth = true
			}

			// Create test handler
			handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			req := httptest.NewRequest("GET", "/", nil)
			if tt.name == "No token - browser request" {
				req.Header.Set("Accept", "text/html")
			}

			// Add valid token if needed
			if tt.validToken {
				tokenString, err := createSession("testuser")
				if err != nil {
					t.Fatalf("Failed to create test session: %v", err)
				}
				req.AddCookie(&http.Cookie{
					Name:  "dfirewall_session",
					Value: tokenString,
				})
			}

			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectRedirect {
				location := w.Header().Get("Location")
				if location != "/login" {
					t.Errorf("Expected redirect to /login, got %s", location)
				}
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {
	// Initialize test environment
	testAuthConfig := &WebUIAuthConfig{
		PasswordAuth:  true,
		Username:      "admin",
		SessionSecret: "test-secret",
		SessionExpiry: 24,
	}

	// Hash the test password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.DefaultCost)
	testAuthConfig.Password = string(hashedPassword)

	testSessionManager := &SessionManager{
		secret:   []byte("test-secret"),
		expiry:   24 * time.Hour,
		sessions: make(map[string]*Session),
	}

	// Save original values
	originalAuthConfig := authConfig
	originalSessionManager := sessionManager

	authConfig = testAuthConfig
	sessionManager = testSessionManager

	// Restore after test
	defer func() {
		authConfig = originalAuthConfig
		sessionManager = originalSessionManager
	}()

	t.Run("GET request returns login page", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/login", nil)
		w := httptest.NewRecorder()

		handleLogin(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "dfirewall") {
			t.Error("Login page should contain 'dfirewall'")
		}

		if !strings.Contains(body, "form") {
			t.Error("Login page should contain login form")
		}
	})

	t.Run("POST with valid credentials", func(t *testing.T) {
		form := url.Values{}
		form.Add("username", "admin")
		form.Add("password", "testpass123")

		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handleLogin(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/" {
			t.Errorf("Expected redirect to /, got %s", location)
		}

		// Check if session cookie is set
		cookies := w.Result().Cookies()
		found := false
		for _, cookie := range cookies {
			if cookie.Name == "dfirewall_session" {
				found = true
				if cookie.Value == "" {
					t.Error("Session cookie should have a value")
				}
				break
			}
		}
		if !found {
			t.Error("Session cookie should be set")
		}
	})

	t.Run("POST with invalid credentials", func(t *testing.T) {
		form := url.Values{}
		form.Add("username", "admin")
		form.Add("password", "wrongpassword")

		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handleLogin(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("Unsupported method", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/login", nil)
		w := httptest.NewRecorder()

		handleLogin(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})
}

func TestHandleLogout(t *testing.T) {
	// Initialize test environment
	testAuthConfig := &WebUIAuthConfig{
		HTTPSEnabled: false,
	}

	testSessionManager := &SessionManager{
		secret:   []byte("test-secret"),
		expiry:   24 * time.Hour,
		sessions: make(map[string]*Session),
	}

	// Save original values
	originalAuthConfig := authConfig
	originalSessionManager := sessionManager

	authConfig = testAuthConfig
	sessionManager = testSessionManager

	// Restore after test
	defer func() {
		authConfig = originalAuthConfig
		sessionManager = originalSessionManager
	}()

	t.Run("Logout clears session cookie", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/logout", nil)
		w := httptest.NewRecorder()

		handleLogout(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/login" {
			t.Errorf("Expected redirect to /login, got %s", location)
		}

		// Check if session cookie is cleared
		cookies := w.Result().Cookies()
		found := false
		for _, cookie := range cookies {
			if cookie.Name == "dfirewall_session" {
				found = true
				if cookie.Value != "" {
					t.Error("Session cookie should be cleared")
				}
				if !cookie.Expires.Before(time.Now()) {
					t.Error("Session cookie should be expired")
				}
				break
			}
		}
		if !found {
			t.Error("Session cookie should be present to clear it")
		}
	})
}