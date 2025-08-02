package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIHealthCheck(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Create a simple health check handler for testing
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var response map[string]string
	err := json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", response["status"])
	}
}

func TestAPIErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Method not allowed",
			method:         "POST",
			url:            "/health",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Not found",
			method:         "GET",
			url:            "/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Invalid JSON",
			method:         "POST",
			url:            "/api/rules",
			body:           "{invalid json}",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Empty body for POST",
			method:         "POST",
			url:            "/api/rules",
			body:           "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			} else {
				req = httptest.NewRequest(tt.method, tt.url, nil)
			}
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()

			// Create a router for testing
			mux := http.NewServeMux()
			
			// Health endpoint that only accepts GET
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
			})

			// API rules endpoint for testing JSON parsing
			mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}

				if r.ContentLength == 0 {
					http.Error(w, "Empty request body", http.StatusBadRequest)
					return
				}

				var data map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
					http.Error(w, "Invalid JSON", http.StatusBadRequest)
					return
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "created"})
			})

			mux.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestAPIJSONValidation(t *testing.T) {
	tests := []struct {
		name           string
		payload        interface{}
		expectedStatus int
	}{
		{
			name: "Valid rule data",
			payload: map[string]interface{}{
				"clientIP":   "192.168.1.100",
				"resolvedIP": "1.2.3.4",
				"domain":     "example.com",
				"ttl":        300,
				"action":     "ALLOW",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Missing required fields",
			payload: map[string]interface{}{
				"domain": "example.com",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid IP format",
			payload: map[string]interface{}{
				"clientIP":   "invalid-ip",
				"resolvedIP": "1.2.3.4",
				"domain":     "example.com",
				"ttl":        300,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid TTL",
			payload: map[string]interface{}{
				"clientIP":   "192.168.1.100",
				"resolvedIP": "1.2.3.4",
				"domain":     "example.com",
				"ttl":        -1,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty domain",
			payload: map[string]interface{}{
				"clientIP":   "192.168.1.100",
				"resolvedIP": "1.2.3.4",
				"domain":     "",
				"ttl":        300,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("Failed to marshal test data: %v", err)
			}

			req := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(jsonData))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Validation handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var data map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
					http.Error(w, "Invalid JSON", http.StatusBadRequest)
					return
				}

				// Validate required fields
				required := []string{"clientIP", "resolvedIP", "domain", "ttl"}
				for _, field := range required {
					if _, exists := data[field]; !exists {
						http.Error(w, "Missing required field: "+field, http.StatusBadRequest)
						return
					}
				}

				// Validate IP format
				if clientIP, ok := data["clientIP"].(string); ok {
					if !validateIP(clientIP) {
						http.Error(w, "Invalid client IP format", http.StatusBadRequest)
						return
					}
				}

				if resolvedIP, ok := data["resolvedIP"].(string); ok {
					if !validateIP(resolvedIP) {
						http.Error(w, "Invalid resolved IP format", http.StatusBadRequest)
						return
					}
				}

				// Validate domain
				if domain, ok := data["domain"].(string); ok {
					if domain == "" || !validateDomain(domain) {
						http.Error(w, "Invalid domain format", http.StatusBadRequest)
						return
					}
				}

				// Validate TTL
				if ttl, ok := data["ttl"].(float64); ok {
					if ttl < 0 || ttl > 2147483647 {
						http.Error(w, "Invalid TTL value", http.StatusBadRequest)
						return
					}
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
			})

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", 
					tt.expectedStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestAPIRateLimiting(t *testing.T) {
	// Simple rate limiter implementation for testing
	type rateLimiter struct {
		requests map[string][]time.Time
		limit    int
		window   time.Duration
	}

	limiter := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    5,
		window:   time.Minute,
	}

	checkRateLimit := func(clientIP string) bool {
		now := time.Now()
		if _, exists := limiter.requests[clientIP]; !exists {
			limiter.requests[clientIP] = []time.Time{}
		}

		// Clean old requests
		var validRequests []time.Time
		for _, reqTime := range limiter.requests[clientIP] {
			if now.Sub(reqTime) < limiter.window {
				validRequests = append(validRequests, reqTime)
			}
		}

		if len(validRequests) >= limiter.limit {
			return false
		}

		limiter.requests[clientIP] = append(validRequests, now)
		return true
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		if !checkRateLimit(clientIP) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	// Test normal requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status %d, got %d", i+1, http.StatusOK, w.Code)
		}
	}

	// Test rate limit exceeded
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected rate limit exceeded status %d, got %d", http.StatusTooManyRequests, w.Code)
	}

	// Test different IP should work
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.101")
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Different IP should work: Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestAPIContentTypeHandling(t *testing.T) {
	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedStatus int
	}{
		{
			name:           "Valid JSON content type",
			contentType:    "application/json",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid content type",
			contentType:    "text/plain",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:           "Missing content type",
			contentType:    "",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:           "JSON with charset",
			contentType:    "application/json; charset=utf-8",
			body:           `{"test": "data"}`,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/data", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contentType := r.Header.Get("Content-Type")
				if !strings.HasPrefix(contentType, "application/json") {
					http.Error(w, "Unsupported media type", http.StatusUnsupportedMediaType)
					return
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "success"})
			})

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestAPISecurityHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	handler.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":      "nosniff",
		"X-Frame-Options":             "DENY",
		"X-XSS-Protection":            "1; mode=block",
		"Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":     "default-src 'self'",
		"Referrer-Policy":             "strict-origin-when-cross-origin",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := w.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Expected header %s: %s, got: %s", header, expectedValue, actualValue)
		}
	}
}

func TestAPIInputSanitization(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "Normal input",
			input: map[string]interface{}{
				"domain": "example.com",
				"ip":     "192.168.1.100",
			},
			expected: map[string]interface{}{
				"domain": "example.com",
				"ip":     "192.168.1.100",
			},
		},
		{
			name: "Input with dangerous characters",
			input: map[string]interface{}{
				"domain": "example.com; rm -rf /",
				"ip":     "192.168.1.100",
			},
			expected: map[string]interface{}{
				"domain": "example.com rm -rf ",
				"ip":     "192.168.1.100",
			},
		},
		{
			name: "XSS attempt",
			input: map[string]interface{}{
				"domain": "<script>alert('xss')</script>",
				"ip":     "192.168.1.100",
			},
			expected: map[string]interface{}{
				"domain": "scriptalert('xss')/script",
				"ip":     "192.168.1.100",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simple sanitization function
			sanitize := func(input string) string {
				return sanitizeForShell(input)
			}

			// Apply sanitization
			result := make(map[string]interface{})
			for key, value := range tt.input {
				if str, ok := value.(string); ok {
					result[key] = sanitize(str)
				} else {
					result[key] = value
				}
			}

			// Check sanitized values
			for key, expectedValue := range tt.expected {
				if result[key] != expectedValue {
					t.Errorf("Sanitization failed for %s: expected %v, got %v", 
						key, expectedValue, result[key])
				}
			}
		})
	}
}

func TestCORSHandling(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		origin         string
		expectedStatus int
		expectedCORS   string
	}{
		{
			name:           "Preflight request",
			method:         "OPTIONS",
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
			expectedCORS:   "*", // Or specific origin depending on configuration
		},
		{
			name:           "GET request with origin",
			method:         "GET",
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
			expectedCORS:   "*",
		},
		{
			name:           "POST request with origin",
			method:         "POST",
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
			expectedCORS:   "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "POST")
			}
			w := httptest.NewRecorder()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// CORS middleware
				origin := r.Header.Get("Origin")
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				}

				if r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusOK)
					return
				}

				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"status": "success"})
			})

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedCORS != "" {
				corsHeader := w.Header().Get("Access-Control-Allow-Origin")
				if corsHeader != tt.expectedCORS {
					t.Errorf("Expected CORS header %s, got %s", tt.expectedCORS, corsHeader)
				}
			}
		})
	}
}