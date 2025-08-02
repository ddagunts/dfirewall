package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// inRange checks if IP is within the specified range
func inRange(ipLow, ipHigh, ip netip.Addr) bool {
	return ip.Compare(ipLow) >= 0 && ip.Compare(ipHigh) <= 0
}

// Register sets up the DNS proxy and starts handling DNS requests
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

	// AI_CONFIG: JSON configuration file for AI-powered threat detection :D
	aiConfigPath := os.Getenv("AI_CONFIG")
	if aiConfigPath != "" {
		config, err := loadAIConfiguration(aiConfigPath)
		if err != nil {
			log.Fatalf("Failed to load AI configuration: %v", err)
		}
		aiConfig = config
		
		// Initialize AI system
		initializeAISystem()
		
		log.Printf("AI_CONFIG loaded from %s: provider=%s, model=%s", aiConfigPath, aiConfig.Provider, aiConfig.Model)
	} else {
		log.Printf("AI_CONFIG env var not set, AI features disabled")
	}

	// CUSTOM_SCRIPT_CONFIG: JSON configuration file for user-provided pass/fail scripts
	customScriptConfigPath := os.Getenv("CUSTOM_SCRIPT_CONFIG")
	if customScriptConfigPath != "" {
		config, err := loadCustomScriptConfiguration(customScriptConfigPath)
		if err != nil {
			log.Fatalf("Failed to load custom script configuration: %v", err)
		}
		customScriptConfig = config
		
		// Initialize custom script system
		initializeCustomScriptSystem()
		
		log.Printf("CUSTOM_SCRIPT_CONFIG loaded from %s: enabled=%v", customScriptConfigPath, customScriptConfig.Enabled)
	} else {
		log.Printf("CUSTOM_SCRIPT_CONFIG env var not set, custom script validation disabled")
	}

	var redisClient *redis.Client
	var err error
	redisClient, err = createRedisClient(redisEnv)
	if err != nil {
		log.Fatalf("Failed to create Redis client: %v", err)
	}

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

	// Initialize Redis blacklist keys if blacklisting is enabled
	if err := initializeRedisBlacklistKeys(redisClient); err != nil {
		log.Fatalf("Failed to initialize Redis blacklist keys: %v", err)
	}

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
				
				// ASSUMPTION: Only process our firewall rule keys (format: "rules:client|ip|domain")
				if strings.HasPrefix(expiredKey, "rules:") {
					// Remove "rules:" prefix and split on pipe (IPv6-safe)
					keyContent := strings.TrimPrefix(expiredKey, "rules:")
					parts := strings.Split(keyContent, "|")
					if len(parts) == 3 {
						clientIP := parts[0]
						resolvedIP := parts[1]
						domain := parts[2]
						
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
				reputationResult := checkReputation(requestedDomain, "domain", redisClient)
				if reputationResult != nil && reputationResult.IsThreat {
					log.Printf("REPUTATION BLOCK: Domain %s requested by %s flagged as malicious (score: %.2f)", 
						requestedDomain, from, reputationResult.ThreatScore)
					// ASSUMPTION: Block malicious domains by returning NXDOMAIN
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				} else if os.Getenv("DEBUG") != "" && reputationResult != nil {
					log.Printf("REPUTATION OK: Domain %s clean (score: %.2f)", 
						requestedDomain, reputationResult.ThreatScore)
				}
			}
			
			// FEATURE: AI-powered domain analysis :D
			if aiConfig != nil && aiConfig.Enabled && aiConfig.DomainAnalysis {
				aiRequest := &AIAnalysisRequest{
					QueryType: "domain",
					Target:    requestedDomain,
					Domain:    requestedDomain,
					ClientIP:  from,
					Timestamp: time.Now(),
				}
				
				aiResult := analyzeWithAI(aiRequest, redisClient)
				if aiResult.IsMalicious && aiResult.Confidence > aiConfig.MinConfidence {
					log.Printf("AI BLOCK: Domain %s requested by %s flagged as malicious by AI (threat_score: %.2f, confidence: %.2f, reasoning: %s)", 
						requestedDomain, from, aiResult.ThreatScore, aiResult.Confidence, aiResult.Reasoning)
					
					// ASSUMPTION: Block AI-detected malicious domains by returning NXDOMAIN
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				} else if os.Getenv("DEBUG") != "" {
					log.Printf("AI OK: Domain %s clean according to AI (threat_score: %.2f, confidence: %.2f)", 
						requestedDomain, aiResult.ThreatScore, aiResult.Confidence)
				}
			}
			
			// FEATURE: Custom script domain validation
			if customScriptConfig != nil && customScriptConfig.Enabled {
				scriptResult := executeCustomScript(requestedDomain, "domain")
				if !scriptResult.IsAllowed {
					log.Printf("CUSTOM SCRIPT BLOCK: Domain %s requested by %s blocked by custom script (exit_code: %d, execution_time: %.3fs, reason: %s)", 
						requestedDomain, from, scriptResult.ExitCode, float64(scriptResult.ExecutionTime)/1000.0, scriptResult.Reason)
					
					// ASSUMPTION: Block custom script denied domains by returning NXDOMAIN
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				} else if os.Getenv("DEBUG") != "" {
					log.Printf("CUSTOM SCRIPT OK: Domain %s allowed by custom script (exit_code: %d, execution_time: %.3fs)", 
						requestedDomain, scriptResult.ExitCode, float64(scriptResult.ExecutionTime)/1000.0)
				}
			}
		}

		// Set up upstream DNS client
		c := new(dns.Client)
		c.Net = "udp"

		// Handle EDNS if enabled
		if ednsAdd == "1" || ednsAdd == "true" {
			// Get client subnet from request (IPv4 or IPv6)
			var clientSubnet *dns.EDNS0_SUBNET

			// Extract client IP and create appropriate subnet
			clientIP := net.ParseIP(from)
			if clientIP != nil {
				clientSubnet = new(dns.EDNS0_SUBNET)
				clientSubnet.Code = dns.EDNS0SUBNET

				if clientIP.To4() != nil {
					// IPv4
					clientSubnet.Family = 1 // IPv4
					clientSubnet.SourceNetmask = 24 // /24 for IPv4
					clientSubnet.SourceScope = 0
					clientSubnet.Address = clientIP.To4()
				} else {
					// IPv6
					clientSubnet.Family = 2 // IPv6
					clientSubnet.SourceNetmask = 64 // /64 for IPv6
					clientSubnet.SourceScope = 0
					clientSubnet.Address = clientIP.To16()
				}

				// Add EDNS0 option to request
				opt := r.IsEdns0()
				if opt == nil {
					opt = new(dns.OPT)
					opt.Hdr.Name = "."
					opt.Hdr.Rrtype = dns.TypeOPT
					r.Extra = append(r.Extra, opt)
				}
				opt.Option = append(opt.Option, clientSubnet)

				if os.Getenv("DEBUG") != "" {
					log.Printf("Added EDNS client subnet: %s", clientSubnet.String())
				}
			}
		}

		// Query upstream DNS
		resp, _, err := c.Exchange(r, upstream)
		if err != nil {
			log.Printf("Error querying upstream DNS: %v", err)
			dns.HandleFailed(w, r)
			return
		}

		// Process the response and extract IPs
		for _, rr := range resp.Answer {
			if rrType, ok := rr.(*dns.A); ok {
				resolvedIP := rrType.A.String()
				domain := rrType.Hdr.Name
				
				// Clamp TTL to maximum 3600 seconds
				originalTTL := rrType.Hdr.Ttl
				if originalTTL > 3600 {
					rrType.Hdr.Ttl = 3600
					if os.Getenv("DEBUG") != "" {
						log.Printf("Clamped TTL from %d to 3600 seconds for %s -> %s", originalTTL, domain, resolvedIP)
					}
				}
				
				ttl := strconv.FormatUint(uint64(rrType.Hdr.Ttl), 10)

				if os.Getenv("DEBUG") != "" {
					log.Printf("A record: %s -> %s (TTL: %s)", domain, resolvedIP, ttl)
				}

				// FEATURE: IP blacklist checking after DNS resolution
				if checkIPBlacklist(resolvedIP, redisClient) {
					if blacklistConfig.LogOnly {
						log.Printf("BLACKLIST LOG: Resolved IP %s for domain %s requested by %s is blacklisted (log-only mode)", resolvedIP, domain, from)
					} else if blacklistConfig.BlockOnMatch {
						log.Printf("BLACKLIST BLOCK: Blocking DNS response with blacklisted IP %s for domain %s requested by %s", resolvedIP, domain, from)
						// ASSUMPTION: Return NXDOMAIN for blacklisted resolved IPs
						m := new(dns.Msg)
						m.SetReply(r)
						m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
						w.WriteMsg(m)
						return
					}
				}

				// FEATURE: IP reputation checking after DNS resolution
				if reputationConfig != nil {
					reputationResult := checkReputation(resolvedIP, "ip", redisClient)
					if reputationResult != nil && reputationResult.IsThreat {
						log.Printf("REPUTATION BLOCK: Resolved IP %s for domain %s requested by %s flagged as malicious (score: %.2f)", 
							resolvedIP, domain, from, reputationResult.ThreatScore)
						// ASSUMPTION: Block malicious resolved IPs by returning NXDOMAIN
						m := new(dns.Msg)
						m.SetReply(r)
						m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
						w.WriteMsg(m)
						return
					} else if os.Getenv("DEBUG") != "" && reputationResult != nil {
						log.Printf("REPUTATION OK: Resolved IP %s clean (score: %.2f)", 
							resolvedIP, reputationResult.ThreatScore)
					}
				}

				// FEATURE: Custom script IP validation
				if customScriptConfig != nil && customScriptConfig.Enabled {
					scriptResult := executeCustomScript(resolvedIP, "ip")
					if !scriptResult.IsAllowed {
						log.Printf("CUSTOM SCRIPT BLOCK: Resolved IP %s for domain %s requested by %s blocked by custom script (exit_code: %d, execution_time: %.3fs, reason: %s)", 
							resolvedIP, domain, from, scriptResult.ExitCode, float64(scriptResult.ExecutionTime)/1000.0, scriptResult.Reason)
						
						// ASSUMPTION: Block custom script denied IPs by returning NXDOMAIN
						m := new(dns.Msg)
						m.SetReply(r)
						m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
						w.WriteMsg(m)
						return
					} else if os.Getenv("DEBUG") != "" {
						log.Printf("CUSTOM SCRIPT OK: Resolved IP %s allowed by custom script (exit_code: %d, execution_time: %.3fs)", 
							resolvedIP, scriptResult.ExitCode, float64(scriptResult.ExecutionTime)/1000.0)
					}
				}

				// Check if this is a new IP for this client
				key := fmt.Sprintf("rules:%s|%s|%s", from, resolvedIP, domain)
				
				exists, err := redisClient.Exists(ctx, key).Result()
				if err != nil {
					log.Printf("Error checking Redis key existence: %v", err)
				}

				isNewRule := exists == 0
				
				// Store in Redis with TTL (minimum 1 second to avoid Redis timeout warnings)
				ttlDuration := time.Duration(rrType.Hdr.Ttl) * time.Second
				if ttlDuration < 1*time.Second {
					ttlDuration = 1 * time.Second
				}
				err = redisClient.Set(ctx, key, "allowed", ttlDuration).Err()
				if err != nil {
					log.Printf("Error storing rule in Redis: %v", err)
				} else if os.Getenv("DEBUG") != "" {
					log.Printf("Stored rule in Redis: %s (TTL: %d seconds)", key, rrType.Hdr.Ttl)
				}

				// Update traffic patterns for AI analysis
				if aiConfig != nil && aiConfig.Enabled && aiConfig.TrafficAnomalies {
					updateTrafficPattern(from, domain, resolvedIP)
				}

				// Execute script based on configuration
				if invoke != "" || scriptConfig != nil {
					executeScript(from, resolvedIP, domain, ttl, "ALLOW", isNewRule)
				}

				// Only process first A record unless HANDLE_ALL_IPS is set
				if handleAllIPs == "" {
					break
				}
			} else if rrType, ok := rr.(*dns.AAAA); ok {
				// Handle IPv6 records similarly
				resolvedIPv6 := rrType.AAAA.String()
				domain := rrType.Hdr.Name
				
				// Clamp TTL to maximum 3600 seconds
				originalTTL := rrType.Hdr.Ttl
				if originalTTL > 3600 {
					rrType.Hdr.Ttl = 3600
					if os.Getenv("DEBUG") != "" {
						log.Printf("Clamped TTL from %d to 3600 seconds for %s -> %s", originalTTL, domain, resolvedIPv6)
					}
				}
				
				ttl := strconv.FormatUint(uint64(rrType.Hdr.Ttl), 10)

				if os.Getenv("DEBUG") != "" {
					log.Printf("AAAA record: %s -> %s (TTL: %s)", domain, resolvedIPv6, ttl)
				}

				// Similar processing for IPv6
				if checkIPBlacklist(resolvedIPv6, redisClient) {
					if blacklistConfig.LogOnly {
						log.Printf("BLACKLIST LOG: Resolved IPv6 %s for domain %s requested by %s is blacklisted (log-only mode)", resolvedIPv6, domain, from)
					} else if blacklistConfig.BlockOnMatch {
						log.Printf("BLACKLIST BLOCK: Blocking DNS response with blacklisted IPv6 %s for domain %s requested by %s", resolvedIPv6, domain, from)
						m := new(dns.Msg)
						m.SetReply(r)
						m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
						w.WriteMsg(m)
						return
					}
				}

				key := fmt.Sprintf("rules:%s|%s|%s", from, resolvedIPv6, domain)
				
				exists, err := redisClient.Exists(ctx, key).Result()
				if err != nil {
					log.Printf("Error checking Redis key existence: %v", err)
				}

				isNewRule := exists == 0
				
				// Store in Redis with TTL (minimum 1 second to avoid Redis timeout warnings)
				ttlDuration := time.Duration(rrType.Hdr.Ttl) * time.Second
				if ttlDuration < 1*time.Second {
					ttlDuration = 1 * time.Second
				}
				err = redisClient.Set(ctx, key, "allowed", ttlDuration).Err()
				if err != nil {
					log.Printf("Error storing IPv6 rule in Redis: %v", err)
				} else if os.Getenv("DEBUG") != "" {
					log.Printf("Stored IPv6 rule in Redis: %s (TTL: %d seconds)", key, rrType.Hdr.Ttl)
				}

				if invoke != "" || scriptConfig != nil {
					executeScript(from, resolvedIPv6, domain, ttl, "ALLOW", isNewRule)
				}

				if handleAllIPs == "" {
					break
				}
			}
		}

		// Send response back to client
		w.WriteMsg(resp)
	})

	return nil
}

// loadScriptConfiguration loads script configuration from JSON file
func loadScriptConfiguration(configPath string) (*ScriptConfiguration, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read script config file: %v", err)
	}
	
	var config ScriptConfiguration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse script JSON config: %v", err)
	}
	
	// Validate client patterns
	for i, client := range config.Clients {
		if err := validateClientPattern(client.ClientPattern); err != nil {
			return nil, fmt.Errorf("client config %d: %v", i, err)
		}
	}
	
	log.Printf("Loaded script configuration with %d client configs", len(config.Clients))
	return &config, nil
}

// findClientConfig finds the matching client configuration for an IP
func findClientConfig(clientIP string) *ClientScriptConfig {
	if scriptConfig == nil {
		return nil
	}
	
	// Process client configs in order - first match wins
	for _, client := range scriptConfig.Clients {
		if matchesClientPattern(clientIP, client.ClientPattern) {
			return &client
		}
	}
	
	return nil // No match found, will use defaults
}

// matchesClientPattern checks if a client IP matches the given pattern
func matchesClientPattern(clientIP, pattern string) bool {
	if strings.HasPrefix(pattern, "regex:") {
		// Regex pattern matching
		regexPattern := strings.TrimPrefix(pattern, "regex:")
		matched, err := regexp.MatchString(regexPattern, clientIP)
		if err != nil {
			log.Printf("WARNING: Invalid regex pattern %s: %v", regexPattern, err)
			return false
		}
		return matched
	}
	
	if strings.Contains(pattern, "/") {
		// CIDR notation matching
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			log.Printf("WARNING: Invalid CIDR pattern %s: %v", pattern, err)
			return false
		}
		
		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}
		
		return cidr.Contains(ip)
	}
	
	// Exact IP matching
	return clientIP == pattern
}

// executeScript executes the appropriate script based on client configuration
func executeScript(clientIP, resolvedIP, domain, ttl, action string, isNewRule bool) {
	// Find client-specific configuration
	clientConfig := findClientConfig(clientIP)
	
	var invokeScript, expireScript string
	var invokeAlways bool
	var environment map[string]string
	
	if clientConfig != nil {
		// Use client-specific settings
		invokeScript = clientConfig.InvokeScript
		expireScript = clientConfig.ExpireScript
		if clientConfig.InvokeAlways != nil {
			invokeAlways = *clientConfig.InvokeAlways
		}
		environment = clientConfig.Environment
		
		if os.Getenv("DEBUG") != "" {
			log.Printf("Using client-specific config for %s: invoke=%s, expire=%s, always=%v", 
				clientIP, invokeScript, expireScript, invokeAlways)
		}
	} else {
		// Use default settings
		if scriptConfig != nil {
			invokeScript = scriptConfig.Defaults.InvokeScript
			expireScript = scriptConfig.Defaults.ExpireScript
			invokeAlways = scriptConfig.Defaults.InvokeAlways
			environment = scriptConfig.Defaults.Environment
		}
		
		// Fall back to environment variables if no config
		if invokeScript == "" {
			invokeScript = os.Getenv("INVOKE_SCRIPT")
		}
		if expireScript == "" {
			expireScript = os.Getenv("EXPIRE_SCRIPT")
		}
		if !invokeAlways {
			invokeAlways = os.Getenv("INVOKE_ALWAYS") != ""
		}
	}
	
	// Determine which script to execute
	var scriptPath string
	if action == "EXPIRE" {
		scriptPath = expireScript
	} else {
		scriptPath = invokeScript
	}
	
	if scriptPath == "" {
		return // No script configured
	}
	
	// Check execution conditions
	if action != "EXPIRE" && !invokeAlways && !isNewRule {
		if os.Getenv("DEBUG") != "" {
			log.Printf("Skipping script execution for existing rule: %s|%s|%s", clientIP, resolvedIP, domain)
		}
		return
	}
	
	// Execute script in background to avoid blocking DNS responses
	go func() {
		// Sanitize inputs for security
		safeClientIP := sanitizeForShell(clientIP)
		safeResolvedIP := sanitizeForShell(resolvedIP)
		safeDomain := sanitizeForShell(domain)
		safeTTL := sanitizeForShell(ttl)
		safeAction := sanitizeForShell(action)
		
		if os.Getenv("DEBUG") != "" {
			log.Printf("Executing script: %s %s %s %s %s %s", scriptPath, safeClientIP, safeResolvedIP, safeDomain, safeTTL, safeAction)
		}
		
		// Execute with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		// Create command with context and arguments
		cmd := exec.CommandContext(ctx, scriptPath, safeClientIP, safeResolvedIP, safeDomain, safeTTL, safeAction)
		
		// Set environment variables (start with minimal base environment)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		if environment != nil {
			for key, value := range environment {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
			}
		}
		
		// Add standard dfirewall environment variables
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("DFIREWALL_CLIENT_IP=%s", clientIP),
			fmt.Sprintf("DFIREWALL_RESOLVED_IP=%s", resolvedIP),
			fmt.Sprintf("DFIREWALL_DOMAIN=%s", domain),
			fmt.Sprintf("DFIREWALL_TTL=%s", ttl),
			fmt.Sprintf("DFIREWALL_ACTION=%s", action),
		)
		
		output, err := cmd.Output()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("Script execution timed out: %s", scriptPath)
			} else {
				log.Printf("Script execution failed: %s, error: %v", scriptPath, err)
			}
		} else if os.Getenv("DEBUG") != "" {
			log.Printf("Script output: %s", string(output))
		}
	}()
}