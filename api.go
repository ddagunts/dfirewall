package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var startTime = time.Now()

// API handler functions

// handleAPIRules returns all firewall rules from Redis
func handleAPIRules(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	
	ctx := context.Background()
	
	// Check if client wants grouped response
	grouped := r.URL.Query().Get("grouped") == "true"
	
	if grouped {
		handleAPIRulesGrouped(w, r, redisClient)
		return
	}
	
	// ASSUMPTION: Get all keys matching our pattern "rules:*"
	keys, err := redisClient.Keys(ctx, "rules:*").Result()
	if err != nil {
		http.Error(w, "Error fetching rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	rules := make([]FirewallRule, 0)
	
	for _, key := range keys {
		// Use secure Redis key parsing with validation
		clientIP, resolvedIP, domain, err := parseRedisKey(key)
		if err != nil {
			log.Printf("WARNING: Skipping invalid Redis key %s: %v", key, err)
			continue
		}
		
		// Additional validation for API display
		if err := validateRedisKeyComponents(clientIP, resolvedIP, domain); err != nil {
			log.Printf("WARNING: Skipping potentially malicious Redis key %s: %v", key, err)
			continue
		}
		
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

// handleAPIRulesGrouped returns firewall rules grouped by client IP
func handleAPIRulesGrouped(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	ctx := context.Background()
	
	// ASSUMPTION: Get all keys matching our pattern "rules:*"
	keys, err := redisClient.Keys(ctx, "rules:*").Result()
	if err != nil {
		http.Error(w, "Error fetching rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Group rules by client IP
	clientRulesMap := make(map[string][]FirewallRule)
	
	for _, key := range keys {
		// Use secure Redis key parsing with validation
		clientIP, resolvedIP, domain, err := parseRedisKey(key)
		if err != nil {
			log.Printf("WARNING: Skipping invalid Redis key %s: %v", key, err)
			continue
		}
		
		// Additional validation for API display
		if err := validateRedisKeyComponents(clientIP, resolvedIP, domain); err != nil {
			log.Printf("WARNING: Skipping potentially malicious Redis key %s: %v", key, err)
			continue
		}
		
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
		
		clientRulesMap[clientIP] = append(clientRulesMap[clientIP], rule)
	}
	
	// Convert map to slice and sort
	clients := make([]ClientRules, 0, len(clientRulesMap))
	totalRules := 0
	
	for clientIP, rules := range clientRulesMap {
		// Sort rules within each client by expiration time (soonest first)
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].ExpiresAt.Before(rules[j].ExpiresAt)
		})
		
		// Find the most recent rule for last updated time
		lastUpdated := time.Time{}
		for _, rule := range rules {
			if rule.CreatedAt.After(lastUpdated) {
				lastUpdated = rule.CreatedAt
			}
		}
		
		clientRules := ClientRules{
			ClientIP:              clientIP,
			RuleCount:             len(rules),
			Rules:                 rules,
			LastUpdated:           lastUpdated,
			TTLGracePeriodSeconds: getTTLGracePeriodForClient(clientIP),
		}
		
		clients = append(clients, clientRules)
		totalRules += len(rules)
	}
	
	// Sort clients by rule count (descending) then by IP
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].RuleCount != clients[j].RuleCount {
			return clients[i].RuleCount > clients[j].RuleCount
		}
		return clients[i].ClientIP < clients[j].ClientIP
	})
	
	response := GroupedRulesResponse{
		TotalClients: len(clients),
		TotalRules:   totalRules,
		Clients:      clients,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIStats returns statistics about the firewall rules
func handleAPIStats(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	
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
		// Use secure Redis key parsing with validation
		clientIP, resolvedIP, domain, err := parseRedisKey(key)
		if err != nil {
			log.Printf("WARNING: Skipping invalid Redis key in stats %s: %v", key, err)
			continue
		}
		
		// Additional validation for API display
		if err := validateRedisKeyComponents(clientIP, resolvedIP, domain); err != nil {
			log.Printf("WARNING: Skipping potentially malicious Redis key in stats %s: %v", key, err)
			continue
		}
		
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
	// Don't Delete key, but expire it
	_, err := redisClient.Set(ctx, req.Key, "", 1*time.Second).Result()
	if err != nil {
		http.Error(w, "Error deleting rule: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	log.Printf("Manually deleted rule: %s", req.Key)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// handleAPIBlacklistIPAdd adds an IP to the Redis blacklist
func handleAPIBlacklistIPAdd(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		IP string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate IP address
	if net.ParseIP(req.IP) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	
	// Check if blacklist is configured
	if blacklistConfig == nil || blacklistConfig.RedisIPKey == "" {
		http.Error(w, "Redis IP blacklist not configured", http.StatusServiceUnavailable)
		return
	}
	
	ctx := context.Background()
	_, err := redisClient.SAdd(ctx, blacklistConfig.RedisIPKey, req.IP).Result()
	if err != nil {
		http.Error(w, "Error adding IP to blacklist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	log.Printf("Added IP %s to blacklist via Web UI", req.IP)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "ip": req.IP})
}

// handleAPIBlacklistIPRemove removes an IP from the Redis blacklist
func handleAPIBlacklistIPRemove(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		IP string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate IP address
	if net.ParseIP(req.IP) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	
	// Check if blacklist is configured
	if blacklistConfig == nil || blacklistConfig.RedisIPKey == "" {
		http.Error(w, "Redis IP blacklist not configured", http.StatusServiceUnavailable)
		return
	}
	
	ctx := context.Background()
	result, err := redisClient.SRem(ctx, blacklistConfig.RedisIPKey, req.IP).Result()
	if err != nil {
		http.Error(w, "Error removing IP from blacklist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	if result == 0 {
		http.Error(w, "IP not found in blacklist", http.StatusNotFound)
		return
	}
	
	log.Printf("Removed IP %s from blacklist via Web UI", req.IP)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "ip": req.IP})
}

// handleAPIBlacklistDomainAdd adds a domain to the Redis blacklist
func handleAPIBlacklistDomainAdd(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Normalize domain (lowercase and validate basic format)
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !strings.Contains(domain, ".") {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}
	
	// Remove trailing dot if present (DNS format)
	domain = strings.TrimSuffix(domain, ".")
	
	// Check if blacklist is configured
	if blacklistConfig == nil || blacklistConfig.RedisDomainKey == "" {
		http.Error(w, "Redis domain blacklist not configured", http.StatusServiceUnavailable)
		return
	}
	
	ctx := context.Background()
	_, err := redisClient.SAdd(ctx, blacklistConfig.RedisDomainKey, domain).Result()
	if err != nil {
		http.Error(w, "Error adding domain to blacklist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	log.Printf("Added domain %s to blacklist via Web UI", domain)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "domain": domain})
}

// handleAPIBlacklistDomainRemove removes a domain from the Redis blacklist
func handleAPIBlacklistDomainRemove(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Normalize domain (lowercase)
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}
	
	// Remove trailing dot if present (DNS format)
	domain = strings.TrimSuffix(domain, ".")
	
	// Check if blacklist is configured
	if blacklistConfig == nil || blacklistConfig.RedisDomainKey == "" {
		http.Error(w, "Redis domain blacklist not configured", http.StatusServiceUnavailable)
		return
	}
	
	ctx := context.Background()
	result, err := redisClient.SRem(ctx, blacklistConfig.RedisDomainKey, domain).Result()
	if err != nil {
		http.Error(w, "Error removing domain from blacklist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	if result == 0 {
		http.Error(w, "Domain not found in blacklist", http.StatusNotFound)
		return
	}
	
	log.Printf("Removed domain %s from blacklist via Web UI", domain)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "domain": domain})
}

// handleAPIBlacklistList returns all blacklisted IPs and domains
func handleAPIBlacklistList(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	ctx := context.Background()
	data := BlacklistData{
		IPs:     []string{},
		Domains: []string{},
	}
	
	// Get blacklisted IPs from Redis
	if blacklistConfig != nil && blacklistConfig.RedisIPKey != "" {
		ips, err := redisClient.SMembers(ctx, blacklistConfig.RedisIPKey).Result()
		if err != nil {
			log.Printf("WARNING: Failed to fetch Redis IP blacklist: %v", err)
		} else {
			data.IPs = ips
		}
	}
	
	// Get blacklisted domains from Redis
	if blacklistConfig != nil && blacklistConfig.RedisDomainKey != "" {
		domains, err := redisClient.SMembers(ctx, blacklistConfig.RedisDomainKey).Result()
		if err != nil {
			log.Printf("WARNING: Failed to fetch Redis domain blacklist: %v", err)
		} else {
			data.Domains = domains
		}
	}
	
	// Sort for consistent output
	sort.Strings(data.IPs)
	sort.Strings(data.Domains)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleAPIReputationCheck performs ad hoc reputation checking for an IP or domain
func handleAPIReputationCheck(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Target string `json:"target"`
		Type   string `json:"type"` // "ip" or "domain"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate input
	req.Target = strings.TrimSpace(req.Target)
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	
	if req.Target == "" {
		http.Error(w, "Target is required", http.StatusBadRequest)
		return
	}
	
	if req.Type != "ip" && req.Type != "domain" {
		http.Error(w, "Type must be 'ip' or 'domain'", http.StatusBadRequest)
		return
	}
	
	// Validate target format
	if req.Type == "ip" {
		if net.ParseIP(req.Target) == nil {
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}
	} else if req.Type == "domain" {
		// Normalize domain
		req.Target = strings.ToLower(req.Target)
		req.Target = strings.TrimSuffix(req.Target, ".")
		if req.Target == "" || !strings.Contains(req.Target, ".") {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
	}
	
	// Check if reputation checking is configured
	if reputationConfig == nil || !reputationConfig.Enabled {
		http.Error(w, "Reputation checking not configured or disabled", http.StatusServiceUnavailable)
		return
	}
	
	// Perform reputation check
	result := checkReputation(req.Target, req.Type, redisClient)
	
	if result == nil {
		// Return neutral result if no reputation services available
		result = &ReputationResult{
			Target:      req.Target,
			ThreatScore: 0.5,
			IsThreat:    false,
			CheckedAt:   time.Now(),
			CacheHit:    false,
		}
	}
	
	log.Printf("Ad hoc reputation check: %s (%s) - ThreatScore: %.2f, IsThreat: %t", 
		req.Target, req.Type, result.ThreatScore, result.IsThreat)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPIAIAnalyze performs ad hoc AI analysis for an IP or domain
func handleAPIAIAnalyze(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Target string `json:"target"`
		Type   string `json:"type"` // "ip" or "domain"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate input
	req.Target = strings.TrimSpace(req.Target)
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	
	if req.Target == "" {
		http.Error(w, "Target is required", http.StatusBadRequest)
		return
	}
	
	if req.Type != "ip" && req.Type != "domain" {
		http.Error(w, "Type must be 'ip' or 'domain'", http.StatusBadRequest)
		return
	}
	
	// Validate target format
	if req.Type == "ip" {
		if net.ParseIP(req.Target) == nil {
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			return
		}
	} else if req.Type == "domain" {
		// Normalize domain
		req.Target = strings.ToLower(req.Target)
		req.Target = strings.TrimSuffix(req.Target, ".")
		if req.Target == "" || !strings.Contains(req.Target, ".") {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
	}
	
	// Check if AI analysis is configured
	if aiConfig == nil || !aiConfig.Enabled {
		http.Error(w, "AI analysis not configured or disabled", http.StatusServiceUnavailable)
		return
	}
	
	// Create AI analysis request
	aiRequest := &AIAnalysisRequest{
		QueryType:   req.Type,
		Target:      req.Target,
		Context:     fmt.Sprintf("web_ui_adhoc_%s_analysis", req.Type),
		Timestamp:   time.Now(),
		Metadata: map[string]string{
			"source": "web_ui_adhoc",
			"target": req.Target,
			"type":   req.Type,
		},
	}
	
	if req.Type == "domain" {
		aiRequest.Domain = req.Target
	} else if req.Type == "ip" {
		aiRequest.IP = req.Target
	}
	
	// Perform AI analysis
	result := analyzeWithAI(aiRequest, redisClient)
	
	if result == nil {
		// Return neutral result if AI analysis fails
		result = &AIAnalysisResult{
			RequestID:   generateRequestID(),
			Target:      req.Target,
			ThreatScore: 0.5,
			Confidence:  0.0,
			IsMalicious: false,
			IsAnomaly:   false,
			Reasoning:   "AI analysis failed or disabled",
			Provider:    "none",
			Timestamp:   time.Now(),
		}
	}
	
	log.Printf("Ad hoc AI analysis: %s (%s) - ThreatScore: %.2f, Confidence: %.2f, Malicious: %t, Provider: %s", 
		req.Target, req.Type, result.ThreatScore, result.Confidence, result.IsMalicious, result.Provider)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleAPIDocs returns comprehensive API documentation
func handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	docs := APIDocumentation{
		Title:       "dfirewall REST API",
		Version:     "1.0.0",
		Description: "Complete REST API for dfirewall - DNS proxy with dynamic firewall management, blacklisting, reputation checking, and AI-powered threat detection",
		BaseURL:     "/api",
		Endpoints: []APIEndpoint{
			{
				Path:        "/api/health",
				Method:      "GET",
				Description: "Health check endpoint - returns system status and component availability",
				Example:     "curl -X GET http://localhost:8080/api/health",
			},
			{
				Path:        "/api/config/status",
				Method:      "GET", 
				Description: "Configuration status - returns enabled features and configuration state",
				Example:     "curl -X GET http://localhost:8080/api/config/status",
			},
			{
				Path:        "/api/stats",
				Method:      "GET",
				Description: "Get firewall statistics - total rules, active clients, unique domains and IPs",
				Example:     "curl -X GET http://localhost:8080/api/stats",
			},
			{
				Path:        "/api/rules",  
				Method:      "GET",
				Description: "List all active firewall rules with TTL and expiration information. Use ?grouped=true for client-grouped format",
				Parameters:  "grouped: boolean (optional) - Return rules grouped by client IP",
				Example:     "curl -X GET http://localhost:8080/api/rules\ncurl -X GET 'http://localhost:8080/api/rules?grouped=true'",
			},
			{
				Path:        "/api/rules/delete",
				Method:      "POST",
				Description: "Delete a specific firewall rule by key",
				Parameters:  "key: string (required) - The rule key to delete",
				Example:     "curl -X POST http://localhost:8080/api/rules/delete -H 'Content-Type: application/json' -d '{\"key\":\"rules:192.168.1.100|1.1.1.1|example.com.\"}'",
			},
			{
				Path:        "/api/blacklist/list",
				Method:      "GET",
				Description: "List all blacklisted IPs and domains from Redis",
				Example:     "curl -X GET http://localhost:8080/api/blacklist/list",
			},
			{
				Path:        "/api/blacklist/ip/add",
				Method:      "POST",
				Description: "Add an IP address to the Redis blacklist",
				Parameters:  "ip: string (required) - Valid IPv4 or IPv6 address",
				Example:     "curl -X POST http://localhost:8080/api/blacklist/ip/add -H 'Content-Type: application/json' -d '{\"ip\":\"192.0.2.1\"}'",
			},
			{
				Path:        "/api/blacklist/ip/remove",
				Method:      "POST",
				Description: "Remove an IP address from the Redis blacklist",
				Parameters:  "ip: string (required) - Valid IPv4 or IPv6 address",
				Example:     "curl -X POST http://localhost:8080/api/blacklist/ip/remove -H 'Content-Type: application/json' -d '{\"ip\":\"192.0.2.1\"}'",
			},
			{
				Path:        "/api/blacklist/domain/add",
				Method:      "POST",
				Description: "Add a domain to the Redis blacklist",
				Parameters:  "domain: string (required) - Valid domain name",
				Example:     "curl -X POST http://localhost:8080/api/blacklist/domain/add -H 'Content-Type: application/json' -d '{\"domain\":\"malicious.com\"}'",
			},
			{
				Path:        "/api/blacklist/domain/remove",
				Method:      "POST",
				Description: "Remove a domain from the Redis blacklist",
				Parameters:  "domain: string (required) - Valid domain name",
				Example:     "curl -X POST http://localhost:8080/api/blacklist/domain/remove -H 'Content-Type: application/json' -d '{\"domain\":\"malicious.com\"}'",
			},
			{
				Path:        "/api/reputation/check",
				Method:      "POST",
				Description: "Perform reputation checking for an IP or domain using configured threat intelligence providers",
				Parameters:  "target: string (required), type: 'ip' or 'domain' (required)",
				Example:     "curl -X POST http://localhost:8080/api/reputation/check -H 'Content-Type: application/json' -d '{\"target\":\"example.com\",\"type\":\"domain\"}'",
			},
			{
				Path:        "/api/ai/analyze",
				Method:      "POST",
				Description: "Perform AI-powered threat analysis for an IP or domain",
				Parameters:  "target: string (required), type: 'ip' or 'domain' (required)",
				Example:     "curl -X POST http://localhost:8080/api/ai/analyze -H 'Content-Type: application/json' -d '{\"target\":\"suspicious-domain.com\",\"type\":\"domain\"}'",
			},
			{
				Path:        "/api/logcollector/stats",
				Method:      "GET",
				Description: "Get log collector statistics including source status, lines processed, and extracted data counts",
				Example:     "curl -X GET http://localhost:8080/api/logcollector/stats",
			},
			{
				Path:        "/api/logcollector/config",
				Method:      "GET",
				Description: "Get log collector configuration including sources, patterns, and connection settings",
				Example:     "curl -X GET http://localhost:8080/api/logcollector/config",
			},
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	
	json.NewEncoder(w).Encode(docs)
}

// handleAPIHealth returns system health and component status
func handleAPIHealth(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	uptime := time.Since(startTime)
	overallStatus := "ok"
	checks := make(map[string]interface{})
	
	// Check Redis connection
	if redisClient != nil {
		ctx := context.Background()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			checks["redis_status"] = "error"
			checks["redis_error"] = err.Error()
			overallStatus = "error"
		} else {
			checks["redis_status"] = "ok"
			
			// Get Redis info
			if info, err := redisClient.Info(ctx, "server").Result(); err == nil {
				lines := strings.Split(info, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "redis_version:") {
						checks["redis_version"] = strings.TrimPrefix(line, "redis_version:")
						break
					}
				}
			}
		}
	} else {
		checks["redis_status"] = "not_configured"
		overallStatus = "warning"
	}
	
	// Check component status
	checks["blacklist_enabled"] = blacklistConfig != nil
	checks["reputation_enabled"] = reputationConfig != nil && reputationConfig.Enabled
	checks["ai_enabled"] = aiConfig != nil && aiConfig.Enabled
	checks["custom_scripts_enabled"] = customScriptConfig != nil && customScriptConfig.Enabled
	checks["log_collector_enabled"] = logCollectorConfig != nil && logCollectorConfig.Enabled
	
	// Add log collector stats if enabled
	if logCollectorConfig != nil && logCollectorConfig.Enabled {
		stats := getLogCollectorStats()
		checks["log_collector_stats"] = map[string]interface{}{
			"total_sources":  stats.TotalSources,
			"active_sources": stats.ActiveSources,
			"total_lines":    stats.TotalLinesRead,
			"ips_extracted":  stats.IPsExtracted,
			"domains_extracted": stats.DomainsExtracted,
		}
	}
	
	health := HealthStatus{
		Status:      overallStatus,
		Uptime:      uptime.String(),
		RedisStatus: checks["redis_status"].(string),
		Checks:      checks,
		LastUpdated: time.Now(),
	}
	
	// Set appropriate HTTP status code
	if overallStatus == "ok" {
		w.WriteHeader(http.StatusOK)
	} else if overallStatus == "warning" {
		w.WriteHeader(http.StatusOK) // Still functional
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleAPIConfigStatus returns configuration and feature status with sensitive data sanitized
func handleAPIConfigStatus(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	config := ConfigStatus{
		ScriptConfig:        scriptConfig,
		BlacklistConfig:     blacklistConfig,
		ReputationConfig:    sanitizeReputationConfig(reputationConfig),
		AIConfig:            sanitizeAIConfig(aiConfig),
		CustomScriptConfig:  customScriptConfig,
		WebUIAuthConfig:     sanitizeAuthConfig(authConfig),
		LogCollectorConfig:  sanitizeLogCollectorConfig(logCollectorConfig),
		SNIInspectionConfig: sniInspectionConfig, // No sensitive data to sanitize
		Environment: map[string]string{
			"UPSTREAM":               os.Getenv("UPSTREAM"),
			"PORT":                   os.Getenv("PORT"),
			"WEB_UI_PORT":            os.Getenv("WEB_UI_PORT"),
			"DEBUG":                  os.Getenv("DEBUG"),
			"HANDLE_ALL_IPS":         os.Getenv("HANDLE_ALL_IPS"),
			"ENABLE_EDNS":            os.Getenv("ENABLE_EDNS"),
			"ENABLE_AAAA_PROCESSING": os.Getenv("ENABLE_AAAA_PROCESSING"),
			"INVOKE_SCRIPT":          os.Getenv("INVOKE_SCRIPT"),
			"INVOKE_ALWAYS":          os.Getenv("INVOKE_ALWAYS"),
			"EXPIRE_SCRIPT":          os.Getenv("EXPIRE_SCRIPT"),
			"LOG_COLLECTOR_CONFIG":   os.Getenv("LOG_COLLECTOR_CONFIG"),
			"SNI_INSPECTION_CONFIG":  os.Getenv("SNI_INSPECTION_CONFIG"),
		},
		LoadedAt: time.Now(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// handleAPILogCollectorStats returns log collector statistics
func handleAPILogCollectorStats(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	stats := getLogCollectorStats()
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Error encoding stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleAPILogCollectorConfig returns log collector configuration
func handleAPILogCollectorConfig(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	if logCollectorConfig == nil {
		http.Error(w, "Log collector not configured", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sanitizeLogCollectorConfig(logCollectorConfig)); err != nil {
		http.Error(w, "Error encoding config: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// sanitizeReputationConfig removes sensitive API keys from reputation configuration
func sanitizeReputationConfig(config *ReputationConfig) *ReputationConfig {
	if config == nil {
		return nil
	}
	
	// Create a copy to avoid modifying the original
	sanitized := *config
	sanitized.Checkers = make([]ReputationChecker, len(config.Checkers))
	
	for i, checker := range config.Checkers {
		sanitized.Checkers[i] = checker
		// Mask API key if present
		if sanitized.Checkers[i].APIKey != "" {
			sanitized.Checkers[i].APIKey = "[REDACTED]"
		}
	}
	
	return &sanitized
}

// sanitizeAIConfig removes sensitive API keys from AI configuration
func sanitizeAIConfig(config *AIConfig) *AIConfig {
	if config == nil {
		return nil
	}
	
	// Create a copy to avoid modifying the original
	sanitized := *config
	// Mask API key if present
	if sanitized.APIKey != "" {
		sanitized.APIKey = "[REDACTED]"
	}
	
	return &sanitized
}

// sanitizeAuthConfig removes sensitive credentials from auth configuration
func sanitizeAuthConfig(config *WebUIAuthConfig) *WebUIAuthConfig {
	if config == nil {
		return nil
	}
	
	// Create a copy to avoid modifying the original
	sanitized := *config
	// Mask sensitive fields
	if sanitized.Password != "" {
		sanitized.Password = "[REDACTED]"
	}
	if sanitized.LDAPBindPass != "" {
		sanitized.LDAPBindPass = "[REDACTED]"
	}
	if sanitized.SessionSecret != "" {
		sanitized.SessionSecret = "[REDACTED]"
	}
	
	return &sanitized
}

// sanitizeLogCollectorConfig removes sensitive credentials from log collector configuration
func sanitizeLogCollectorConfig(config *LogCollectorConfig) *LogCollectorConfig {
	if config == nil {
		return nil
	}
	
	// Create a copy to avoid modifying the original
	sanitized := *config
	sanitized.Sources = make([]LogSource, len(config.Sources))
	
	for i, source := range config.Sources {
		sanitized.Sources[i] = source
		// Mask SSH credentials if present
		if sanitized.Sources[i].Password != "" {
			sanitized.Sources[i].Password = "[REDACTED]"
		}
		if sanitized.Sources[i].PrivateKeyData != "" {
			sanitized.Sources[i].PrivateKeyData = "[REDACTED]"
		}
		if sanitized.Sources[i].Passphrase != "" {
			sanitized.Sources[i].Passphrase = "[REDACTED]"
		}
	}
	
	return &sanitized
}

// SNI Inspection API Handlers

// handleAPISNIStats returns SNI inspection statistics
func handleAPISNIStats(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SNI inspection is not enabled",
		})
		return
	}

	stats := getSNIInspectionStats()
	if stats == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SNI inspection statistics not available",
		})
		return
	}

	json.NewEncoder(w).Encode(stats)
}

// handleAPISNIConnections returns active SNI connections
func handleAPISNIConnections(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SNI inspection is not enabled",
		})
		return
	}

	connections := getActiveSNIConnections()
	
	response := map[string]interface{}{
		"active_connections": len(connections),
		"connections":        connections,
		"timestamp":          time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPISNIConfig returns sanitized SNI inspection configuration
func handleAPISNIConfig(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	if sniInspectionConfig == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SNI inspection configuration not available",
		})
		return
	}

	// Return sanitized configuration (no sensitive data to hide for SNI inspection)
	json.NewEncoder(w).Encode(sniInspectionConfig)
}

// handleAPISNIValidate validates SNI for a specific client and domain combination  
func handleAPISNIValidate(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	if sniInspectionConfig == nil || !sniInspectionConfig.Enabled {
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "SNI inspection is not enabled",
		})
		return
	}

	var request struct {
		ClientIP        string `json:"client_ip"`
		RequestedDomain string `json:"requested_domain"`
		SNIDomain       string `json:"sni_domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid JSON request",
		})
		return
	}

	// Validate inputs
	if request.ClientIP == "" || request.RequestedDomain == "" || request.SNIDomain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "client_ip, requested_domain, and sni_domain are required",
		})
		return
	}

	// Validate IP format
	if net.ParseIP(request.ClientIP) == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid client_ip format",
		})
		return
	}

	// Check if SNI inspection would be used for this client/domain
	useSNIInspection, proxyIP := shouldUseSNIInspection(request.ClientIP, request.RequestedDomain)
	
	// Validate the SNI
	isValid := validateSNI(request.ClientIP, request.RequestedDomain, request.SNIDomain)

	response := map[string]interface{}{
		"client_ip":         request.ClientIP,
		"requested_domain":  request.RequestedDomain,
		"sni_domain":        request.SNIDomain,
		"uses_sni_inspection": useSNIInspection,
		"proxy_ip":          proxyIP,
		"is_valid":          isValid,
		"would_be_blocked":  useSNIInspection && !isValid && sniInspectionConfig.StrictValidation && !sniInspectionConfig.LogOnly,
		"timestamp":         time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIClientHistory returns historical DNS lookups for a specific client IP
func handleAPIClientHistory(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	// Extract client IP from URL path
	// Expected format: /api/client/history/{clientIP}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		http.Error(w, "Client IP is required in URL path", http.StatusBadRequest)
		return
	}
	
	clientIP := pathParts[3]
	
	// Validate client IP
	if !validateIP(clientIP) {
		http.Error(w, "Invalid client IP address", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	historyKey := fmt.Sprintf("history:client:%s", clientIP)

	// Parse query parameters for filtering
	query := r.URL.Query()
	
	// Time range parameters (optional)
	var startTime, endTime time.Time
	if startStr := query.Get("start"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			startTime = t
		}
	}
	if endStr := query.Get("end"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			endTime = t
		}
	}

	// Set defaults if not provided
	if startTime.IsZero() {
		startTime = time.Now().AddDate(0, 0, -30) // Default: last 30 days
	}
	if endTime.IsZero() {
		endTime = time.Now()
	}

	// Limit parameter (default 1000)
	limit := int64(1000)
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 64); err == nil && l > 0 && l <= 10000 {
			limit = l
		}
	}

	// Query Redis sorted set by score range (timestamp)
	startScore := float64(startTime.Unix())
	endScore := float64(endTime.Unix())
	
	members, err := redisClient.ZRevRangeByScore(ctx, historyKey, &redis.ZRangeBy{
		Min:    fmt.Sprintf("%f", startScore),
		Max:    fmt.Sprintf("%f", endScore),
		Count:  limit,
	}).Result()
	
	if err != nil {
		if err == redis.Nil {
			// No historical data found - return empty response
			response := ClientHistoryResponse{
				ClientIP:     clientIP,
				TotalLookups: 0,
				Lookups:      []HistoricalLookup{},
				StartTime:    startTime,
				EndTime:      endTime,
			}
			json.NewEncoder(w).Encode(response)
			return
		}
		http.Error(w, "Error fetching client history: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse JSON entries
	lookups := make([]HistoricalLookup, 0, len(members))
	for _, member := range members {
		var lookup HistoricalLookup
		if err := json.Unmarshal([]byte(member), &lookup); err != nil {
			log.Printf("WARNING: Error unmarshaling historical lookup entry: %v", err)
			continue
		}
		lookups = append(lookups, lookup)
	}

	// Build response
	response := ClientHistoryResponse{
		ClientIP:     clientIP,
		TotalLookups: len(lookups),
		Lookups:      lookups,
		StartTime:    startTime,
		EndTime:      endTime,
	}

	json.NewEncoder(w).Encode(response)
}