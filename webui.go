package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Simple rate limiting configuration
const (
	maxRequestsPerMinute = 60  // Allow 60 requests per minute per IP
	rateWindowMinutes    = 1   // 1 minute sliding window
	maxLoginAttempts     = 5   // Allow 5 login attempts per minute per IP
)

// requestRecord tracks requests for rate limiting
type requestRecord struct {
	count     int
	lastReset time.Time
}

// rateLimiter provides simple in-memory rate limiting
type rateLimiter struct {
	mu      sync.RWMutex
	clients map[string]*requestRecord
	logins  map[string]*requestRecord // Separate limit for login attempts
}

var globalRateLimiter = &rateLimiter{
	clients: make(map[string]*requestRecord),
	logins:  make(map[string]*requestRecord),
}

// protectedHandler combines rate limiting and authentication middleware
func protectedHandler(handler http.HandlerFunc) http.HandlerFunc {
	return rateLimitMiddleware(authMiddleware(handler))
}

// startWebUI starts the web UI server for rule management
func startWebUI(port string, redisClient *redis.Client) {
	// Initialize authentication system
	initAuth()
	
	// Start periodic session cleanup
	periodicSessionCleanup()
	
	// Start rate limit cleanup
	startRateLimitCleanup()
	
	// Web UI interface binding configuration
	webuiBindIP := os.Getenv("WEBUI_BIND_IP")
	if webuiBindIP == "" {
		webuiBindIP = "" // Default to bind to all interfaces (0.0.0.0)
		log.Printf("Web UI will bind to all interfaces, set WEBUI_BIND_IP to restrict")
	} else {
		if err := validateBindIP(webuiBindIP); err != nil {
			log.Fatalf("Invalid WEBUI_BIND_IP: %v", err)
		}
		log.Printf("Web UI will bind to interface: %s", webuiBindIP)
	}
	
	// Construct Web UI server address
	webuiAddr := webuiBindIP + ":" + port
	
	log.Printf("Starting web UI server on %s (HTTPS: %v, Auth: %v)", 
		webuiAddr, authConfig.HTTPSEnabled, isAuthEnabled())
	
	// Create a new ServeMux to avoid conflicts with global default ServeMux
	mux := http.NewServeMux()
	
	// Authentication routes (always available) with rate limiting
	mux.HandleFunc("/login", rateLimitMiddleware(handleLogin))
	mux.HandleFunc("/logout", rateLimitMiddleware(handleLogout))
	
	// Protected routes with rate limiting and authentication
	
	mux.HandleFunc("/", protectedHandler(handleUIHome))
	mux.HandleFunc("/api/rules", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIRules(w, r, redisClient)
	}))
	mux.HandleFunc("/api/stats", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIStats(w, r, redisClient)
	}))
	mux.HandleFunc("/api/rules/delete", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIDeleteRule(w, r, redisClient)
	}))
	mux.HandleFunc("/api/blacklist/ip/add", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlacklistIPAdd(w, r, redisClient)
	}))
	mux.HandleFunc("/api/blacklist/ip/remove", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlacklistIPRemove(w, r, redisClient)
	}))
	mux.HandleFunc("/api/blacklist/domain/add", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlacklistDomainAdd(w, r, redisClient)
	}))
	mux.HandleFunc("/api/blacklist/domain/remove", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlacklistDomainRemove(w, r, redisClient)
	}))
	mux.HandleFunc("/api/blacklist/list", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlacklistList(w, r, redisClient)
	}))
	mux.HandleFunc("/api/reputation/check", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIReputationCheck(w, r, redisClient)
	}))
	mux.HandleFunc("/api/ai/analyze", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIAIAnalyze(w, r, redisClient)
	}))
	mux.HandleFunc("/api/docs", protectedHandler(handleAPIDocs))
	mux.HandleFunc("/api/health", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIHealth(w, r, redisClient)
	}))
	mux.HandleFunc("/api/config/status", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIConfigStatus(w, r, redisClient)
	}))
	mux.HandleFunc("/api/logcollector/stats", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPILogCollectorStats(w, r, redisClient)
	}))
	mux.HandleFunc("/api/logcollector/config", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPILogCollectorConfig(w, r, redisClient)
	}))
	
	// SNI Inspection API endpoints
	mux.HandleFunc("/api/sni/stats", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPISNIStats(w, r, redisClient)
	}))
	mux.HandleFunc("/api/sni/connections", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPISNIConnections(w, r, redisClient)
	}))
	mux.HandleFunc("/api/sni/config", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPISNIConfig(w, r, redisClient)
	}))
	mux.HandleFunc("/api/sni/validate", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPISNIValidate(w, r, redisClient)
	}))
	
	// Client history endpoints
	mux.HandleFunc("/api/client/history/", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIClientHistory(w, r, redisClient)
	}))
	
	// All clients endpoint
	mux.HandleFunc("/api/clients", protectedHandler(func(w http.ResponseWriter, r *http.Request) {
		handleAPIAllClients(w, r, redisClient)
	}))
	
	server := &http.Server{
		Addr:    webuiAddr,
		Handler: mux, // Use our custom ServeMux instead of default
		// Set reasonable timeouts to prevent resource exhaustion
		ReadTimeout:  30 * time.Second,  // Increased for authentication
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	// Start server with HTTPS or HTTP based on configuration
	if authConfig.HTTPSEnabled && authConfig.CertFile != "" && authConfig.KeyFile != "" {
		log.Printf("Starting HTTPS server with cert: %s, key: %s", authConfig.CertFile, authConfig.KeyFile)
		if err := server.ListenAndServeTLS(authConfig.CertFile, authConfig.KeyFile); err != nil {
			log.Printf("HTTPS Web UI server failed: %v", err)
		}
	} else {
		if authConfig.HTTPSEnabled {
			log.Printf("HTTPS enabled but cert/key files not configured, falling back to HTTP")
		}
		if err := server.ListenAndServe(); err != nil {
			log.Printf("HTTP Web UI server failed: %v", err)
		}
	}
}

// handleUIHome serves the main HTML page
func handleUIHome(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
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
        .stats { display: flex; gap: 15px; margin: 15px 0; }
        .stat-box { background: #007acc; color: white; padding: 10px; border-radius: 5px; flex: 1; text-align: center; }
        .stat-box h3 { margin: 0; font-size: 18px; }
        .stat-box p { margin: 3px 0 0 0; font-size: 12px; }
        
        /* View Toggle Buttons */
        .view-toggle { margin: 20px 0; text-align: center; }
        .view-btn { background: #6c757d; color: white; border: none; padding: 8px 12px; border-radius: 5px; cursor: pointer; margin: 0 3px; font-size: 13px; white-space: nowrap; flex-shrink: 0; }
        .view-btn.active { background: #007acc; }
        .view-btn:hover { background: #5a6268; }
        .view-btn.active:hover { background: #0056b3; }
        
        /* Client-grouped view styles */
        .client-section { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
        .client-header { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ddd; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .client-header:hover { background: #e9ecef; }
        .client-header h3 { margin: 0; color: #495057; }
        .client-stats { display: flex; gap: 15px; align-items: center; font-size: 14px; color: #6c757d; flex-wrap: nowrap; min-width: 0; }
        .client-stats span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; flex-shrink: 1; }
        .client-badge { background: #007acc; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .collapse-icon { font-size: 18px; color: #6c757d; transition: transform 0.3s; }
        .client-section.collapsed .collapse-icon { transform: rotate(-90deg); }
        .client-rules { background: white; }
        .client-section.collapsed .client-rules { display: none; }
        
        /* Traditional table styles */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:hover { background-color: #f9f9f9; }
        .client-rules table { margin-top: 0; }
        .client-rules th { background-color: #fff; font-size: 14px; padding: 10px 12px; }
        
        /* Compact rule styles for client view */
        .rule-row { padding: 12px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .rule-row:hover { background-color: #f8f9fa; }
        .rule-info { flex: 1; }
        .rule-primary { font-weight: bold; color: #333; margin-bottom: 4px; }
        .rule-secondary { font-size: 13px; color: #666; }
        .rule-meta { font-size: 12px; color: #999; margin-top: 4px; }
        .rule-actions { display: flex; gap: 8px; }
        
        .delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px; }
        .delete-btn:hover { background: #c82333; }
        .refresh-btn { background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
        .refresh-btn:hover { background: #218838; }
        
        /* Unified button styling for top navigation buttons */
        .top-nav-btn { 
            background: #6c757d; 
            color: white; 
            border: none; 
            padding: 8px 12px; 
            border-radius: 5px; 
            cursor: pointer; 
            text-decoration: none; 
            display: inline-block; 
            font-size: 13px;
            text-align: center;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .top-nav-btn:hover { background: #5a6268; }
        .top-nav-btn.refresh { background: #28a745; }
        .top-nav-btn.refresh:hover { background: #218838; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .error { color: #dc3545; text-align: center; padding: 20px; }
        .domain { word-break: break-all; max-width: 200px; }
        .ttl { font-family: monospace; }
        
        /* Empty state */
        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state h3 { color: #999; margin-bottom: 10px; }
        .empty-state p { font-size: 14px; line-height: 1.5; }
        
        /* Tab styling */
        .tab-container { margin-top: 30px; border-top: 2px solid #007acc; }
        .tab-nav { display: flex; background: #f8f9fa; border-bottom: 1px solid #ddd; margin: 0; padding: 0; list-style: none; }
        .tab-nav li { margin: 0; }
        .tab-nav button { 
            background: none; 
            border: none; 
            padding: 15px 25px; 
            cursor: pointer; 
            border-bottom: 3px solid transparent; 
            font-size: 14px; 
            color: #495057;
            transition: all 0.3s ease;
        }
        .tab-nav button:hover { background: #e9ecef; color: #007acc; }
        .tab-nav button.active { 
            background: white; 
            color: #007acc; 
            border-bottom-color: #007acc; 
            font-weight: bold;
        }
        .tab-content { background: white; padding: 25px; border-radius: 0 0 8px 8px; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>dfirewall - Firewall Rule Management</h1>
        
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <button class="top-nav-btn refresh" onclick="loadData()">🔄 Refresh</button>
                <a href="/api/docs" target="_blank" class="top-nav-btn">📖 API Docs</a>
                <button class="top-nav-btn" onclick="toggleSettings()">⚙️ Settings</button>
                <button class="top-nav-btn" onclick="toggleClientHistory()">📊 History</button>
                <button class="top-nav-btn" onclick="toggleAllClients()">👥 Clients</button>
                <button class="top-nav-btn" onclick="toggleSecurityPanel()">🛡️ Security</button>
                <button class="view-btn active" id="groupedViewBtn" onclick="switchView('grouped')">👥 Grouped</button>
                <button class="view-btn" id="tableViewBtn" onclick="switchView('table')">📋 Table</button>
            </div>
            <div id="authStatus" style="display: none;">
                <span style="color: #666; margin-right: 10px;">Logged in as: <strong id="currentUser">-</strong></span>
                <a href="/logout" style="background: #dc3545; color: white; text-decoration: none; padding: 8px 15px; border-radius: 3px; font-size: 14px;">🚪 Logout</a>
            </div>
        </div>
        
        <!-- Settings Panel -->
        <div id="settingsPanel" style="display: none; background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 15px 0; color: #495057;">⚙️ Settings</h3>
            <div style="display: flex; gap: 30px; flex-wrap: wrap;">
                <div>
                    <label for="refreshRate" style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Auto-refresh Interval:</label>
                    <select id="refreshRate" onchange="updateRefreshRate()" style="padding: 8px; border: 1px solid #ddd; border-radius: 3px; background: white;">
                        <option value="0">Disabled</option>
                        <option value="5000">5 seconds</option>
                        <option value="10000">10 seconds</option>
                        <option value="15000">15 seconds</option>
                        <option value="30000" selected>30 seconds (default)</option>
                        <option value="60000">1 minute</option>
                        <option value="120000">2 minutes</option>
                        <option value="300000">5 minutes</option>
                    </select>
                </div>
                <div>
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Refresh Status:</label>
                    <span id="refreshStatus" style="padding: 6px 12px; border-radius: 15px; font-size: 12px; font-weight: bold;">Active (30s)</span>
                </div>
                <div>
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Next Refresh:</label>
                    <span id="nextRefresh" style="color: #666; font-family: monospace;">-</span>
                </div>
            </div>
        </div>
        
        <!-- Client History Panel -->
        <div id="clientHistoryPanel" style="display: none; background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 15px 0; color: #495057;">📊 Client DNS Lookup History</h3>
            <div style="display: flex; gap: 15px; flex-wrap: wrap; align-items: end; margin-bottom: 20px;">
                <div>
                    <label for="clientIPInput" style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Client IP Address:</label>
                    <input type="text" id="clientIPInput" placeholder="192.168.1.100" style="padding: 8px; border: 1px solid #ddd; border-radius: 3px; width: 150px;">
                </div>
                <div>
                    <label for="historyDays" style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Time Range:</label>
                    <select id="historyDays" style="padding: 8px; border: 1px solid #ddd; border-radius: 3px; background: white;">
                        <option value="1">Last 24 hours</option>
                        <option value="3">Last 3 days</option>
                        <option value="7">Last 7 days</option>
                        <option value="30" selected>Last 30 days</option>
                        <option value="90">Last 90 days</option>
                    </select>
                </div>
                <div>
                    <label for="historyLimit" style="display: block; margin-bottom: 5px; font-weight: bold; color: #495057;">Limit:</label>
                    <select id="historyLimit" style="padding: 8px; border: 1px solid #ddd; border-radius: 3px; background: white;">
                        <option value="100">100 entries</option>
                        <option value="500">500 entries</option>
                        <option value="1000" selected>1000 entries</option>
                        <option value="5000">5000 entries</option>
                    </select>
                </div>
                <button onclick="loadClientHistory()" style="background: #007acc; color: white; border: none; padding: 8px 20px; border-radius: 3px; cursor: pointer;">🔍 Search</button>
            </div>
            
            <!-- History Results -->
            <div id="historyResults" style="display: none;">
                <div id="historyStats" style="margin-bottom: 15px; padding: 10px; background: white; border-radius: 5px; border: 1px solid #ddd;">
                    <strong>Results: </strong><span id="historyCount">0</span> lookups 
                    | <strong>Period: </strong><span id="historyPeriod">-</span>
                </div>
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px; background: white;">
                    <table style="width: 100%; margin: 0;">
                        <thead>
                            <tr style="background: #f8f9fa;">
                                <th>Timestamp</th>
                                <th>Domain</th>
                                <th>Resolved IP</th>
                                <th>TTL</th>
                            </tr>
                        </thead>
                        <tbody id="historyTableBody">
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="historyLoading" style="display: none; text-align: center; padding: 20px; color: #666;">
                Loading client history...
            </div>
            
            <div id="historyError" style="display: none; color: #dc3545; text-align: center; padding: 20px;">
            </div>
        </div>
        
        <!-- All Clients Panel -->
        <div id="allClientsPanel" style="display: none; background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 15px 0; color: #495057;">👥 All Clients Ever Seen</h3>
            <div style="display: flex; gap: 15px; align-items: center; margin-bottom: 20px;">
                <button onclick="loadAllClients()" style="background: #007acc; color: white; border: none; padding: 8px 20px; border-radius: 3px; cursor: pointer;">🔍 Load Clients</button>
                <span id="allClientsCount" style="color: #666; font-size: 14px;"></span>
            </div>
            
            <!-- Clients Results -->
            <div id="allClientsResults" style="display: none;">
                <div style="max-height: 500px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px; background: white;">
                    <table style="width: 100%; margin: 0;">
                        <thead>
                            <tr style="background: #f8f9fa;">
                                <th>Client IP</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                                <th>Total Lookups</th>
                                <th>Active Rules</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="allClientsTableBody">
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="allClientsLoading" style="display: none; text-align: center; padding: 20px; color: #666;">
                Loading clients...
            </div>
            
            <div id="allClientsError" style="display: none; color: #dc3545; text-align: center; padding: 20px;">
            </div>
        </div>
        
        <!-- Security Management Panel -->
        <div id="securityPanel" style="display: none; background: #f8f9fa; border: 1px solid #ddd; border-radius: 8px; padding: 0; margin-bottom: 20px;">
            <div class="tab-nav" style="margin: 0; border-radius: 8px 8px 0 0; overflow: hidden;">
                <button class="tab-btn active" onclick="switchSecurityTab('blacklist')" style="border-radius: 8px 0 0 0;">🚫 Blacklist Management</button>
                <button class="tab-btn" onclick="switchSecurityTab('analysis')">🤖 Reputation & AI Analysis</button>
            </div>
            <div style="padding: 25px; background: white; border-radius: 0 0 8px 8px;">
                <!-- Blacklist Management Tab -->
                <div id="blacklistSecurityTab" class="tab-panel active">
                    <h3 style="margin: 0 0 20px 0; color: #495057;">🚫 Blacklist Management</h3>
                    
                    <div style="display: flex; gap: 20px; margin: 20px 0;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 15px 0;">Add to Blacklist</h4>
                            <div style="margin-bottom: 10px;">
                                <input type="text" id="ipInput" placeholder="Enter IP address" style="width: 70%; padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                                <button onclick="addIPToBlacklist()" style="background: #dc3545; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer;">Block IP</button>
                            </div>
                            <div style="margin-bottom: 10px;">
                                <input type="text" id="domainInput" placeholder="Enter domain name" style="width: 70%; padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                                <button onclick="addDomainToBlacklist()" style="background: #dc3545; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer;">Block Domain</button>
                            </div>
                        </div>
                        
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 15px 0;">Current Blacklists</h4>
                            <button onclick="loadBlacklists()" style="background: #17a2b8; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer; margin-bottom: 10px;">🔄 Refresh Blacklists</button>
                            <div id="blacklistData" style="font-size: 12px; max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 3px; background: #f8f9fa;"></div>
                        </div>
                    </div>
                </div>
                
                <!-- Reputation & AI Analysis Tab -->
                <div id="analysisSecurityTab" class="tab-panel">
                    <h3 style="margin: 0 0 20px 0; color: #495057;">🤖 Reputation & AI Analysis</h3>
                    
                    <div style="display: flex; gap: 20px; margin: 20px 0;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 15px 0;">Analyze Target</h4>
                            <div style="margin-bottom: 15px;">
                                <input type="text" id="analyzeInput" placeholder="Enter IP address or domain name" style="width: 60%; padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                                <select id="analyzeType" style="padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px;">
                                    <option value="ip">IP Address</option>
                                    <option value="domain">Domain</option>
                                </select>
                            </div>
                            <div style="margin-bottom: 10px;">
                                <button onclick="checkReputation()" style="background: #ffc107; color: black; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer; margin-right: 10px;">🛡️ Check Reputation</button>
                                <button onclick="analyzeWithAI()" style="background: #17a2b8; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer;">🤖 AI Analysis</button>
                            </div>
                        </div>
                    </div>
                    
                    <div id="analysisResults" style="margin-top: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa; min-height: 50px; max-height: 400px; overflow-y: auto;">
                        <em style="color: #666;">Analysis results will appear here...</em>
                    </div>
                </div>
            </div>
        </div>
        
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
        
        <!-- Grouped View (Default) -->
        <div id="groupedView" style="display: none;">
            <div id="clientsContainer"></div>
        </div>
        
        <!-- Traditional Table View -->
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
        
        let currentView = 'grouped'; // Default view
        let refreshInterval = 30000; // Default 30 seconds
        let refreshTimer = null;
        let nextRefreshTime = null;
        let countdownTimer = null;
        
        // Switch between grouped and table views
        function switchView(view) {
            currentView = view;
            
            // Update button states
            document.getElementById('groupedViewBtn').className = view === 'grouped' ? 'view-btn active' : 'view-btn';
            document.getElementById('tableViewBtn').className = view === 'table' ? 'view-btn active' : 'view-btn';
            
            // Load data for the selected view
            loadData();
        }
        
        async function loadData(showLoading = true) {
            if (showLoading) {
                document.getElementById('loading').style.display = 'block';
                document.getElementById('error').style.display = 'none';
                document.getElementById('rulesTable').style.display = 'none';
                document.getElementById('groupedView').style.display = 'none';
            }
            
            try {
                // Load statistics with smooth update
                await loadStats();
                
                if (currentView === 'grouped') {
                    await loadGroupedView(showLoading);
                } else {
                    await loadTableView(showLoading);
                }
                
            } catch (error) {
                if (showLoading) {
                    document.getElementById('loading').style.display = 'none';
                }
                document.getElementById('error').style.display = 'block';
                
                // Provide more detailed error information
                let errorMsg = 'Error loading data: ' + error.message;
                if (error.name === 'TypeError' && error.message.includes('fetch')) {
                    errorMsg = 'Cannot connect to dfirewall API server. Please check if the server is running.';
                }
                
                document.getElementById('error').textContent = errorMsg;
                console.error('Detailed error:', error);
            }
        }
        
        async function loadStats() {
            try {
                const statsResponse = await fetch('/api/stats');
                if (!statsResponse.ok) {
                    throw new Error('Stats API failed: ' + statsResponse.status + ' ' + statsResponse.statusText);
                }
                const stats = await statsResponse.json();
                
                // Smooth update of statistics with animation
                updateStatWithAnimation('totalRules', stats.total_rules);
                updateStatWithAnimation('activeClients', stats.active_clients);
                updateStatWithAnimation('uniqueDomains', stats.unique_domains);
                updateStatWithAnimation('uniqueIPs', stats.unique_ips);
            } catch (error) {
                // Silently fail stats updates during auto-refresh to avoid disrupting user experience
                console.warn('Stats update failed:', error.message);
            }
        }
        
        function updateStatWithAnimation(elementId, newValue) {
            const element = document.getElementById(elementId);
            const currentValue = element.textContent;
            
            if (currentValue !== newValue.toString()) {
                element.style.transition = 'all 0.3s ease';
                element.style.transform = 'scale(1.1)';
                element.style.color = '#28a745';
                
                setTimeout(() => {
                    element.textContent = newValue;
                    element.style.transform = 'scale(1)';
                    element.style.color = '';
                }, 150);
            }
        }
        
        async function loadGroupedView(showLoading = true) {
            try {
                // Load grouped rules
                const rulesResponse = await fetch('/api/rules?grouped=true');
                if (!rulesResponse.ok) {
                    throw new Error('Grouped Rules API failed: ' + rulesResponse.status + ' ' + rulesResponse.statusText);
                }
                const groupedData = await rulesResponse.json();
                
                const container = document.getElementById('clientsContainer');
                
                if (groupedData.clients.length === 0) {
                    if (showLoading || container.innerHTML === '') {
                        container.innerHTML = '<div class="empty-state">' +
                            '<h3>No firewall rules found</h3>' +
                            '<p>Rules will appear here after DNS queries are processed through dfirewall.<br>' +
                            'Each client that makes DNS requests will be shown with their associated firewall rules.</p>' +
                            '</div>';
                    }
                } else {
                    updateGroupedViewSmooth(container, groupedData.clients);
                }
                
                if (showLoading) {
                    document.getElementById('loading').style.display = 'none';
                }
                document.getElementById('groupedView').style.display = 'block';
            } catch (error) {
                if (!showLoading) {
                    // Silent failure for auto-refresh
                    console.warn('Grouped view update failed:', error.message);
                    return;
                }
                throw error; // Re-throw for manual refresh to show error
            }
        }
        
        function updateGroupedViewSmooth(container, newClients) {
            const existingClients = new Map();
            const existingElements = container.querySelectorAll('.client-section');
            
            // Build map of existing client sections
            existingElements.forEach(element => {
                const clientIP = element.id.replace('client-', '').replace(/_/g, ':').replace(/:/g, '.').replace(/\./g, ':');
                if (clientIP.includes('_')) {
                    // Handle IPv6 or complex IPs
                    const parts = element.id.split('_');
                    if (parts.length > 2) {
                        existingClients.set(element.id, element);
                    } else {
                        existingClients.set(clientIP.replace(/_/g, '.'), element);
                    }
                } else {
                    existingClients.set(clientIP, element);
                }
            });
            
            // Create a set of new client IPs for tracking
            const newClientIPs = new Set(newClients.map(client => client.client_ip));
            
            // Remove clients that no longer exist with fade-out animation
            existingElements.forEach(element => {
                const clientIP = extractClientIPFromElement(element);
                if (!newClientIPs.has(clientIP)) {
                    element.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    element.style.opacity = '0';
                    element.style.transform = 'translateX(-20px)';
                    setTimeout(() => element.remove(), 500);
                }
            });
            
            // Update or add clients
            newClients.forEach(client => {
                const existingElement = findExistingClientElement(container, client.client_ip);
                
                if (existingElement) {
                    // Update existing client
                    updateClientSectionSmooth(existingElement, client);
                } else {
                    // Add new client with fade-in animation
                    const clientSection = createClientSection(client);
                    clientSection.style.opacity = '0';
                    clientSection.style.transform = 'translateX(20px)';
                    clientSection.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    
                    container.appendChild(clientSection);
                    
                    // Trigger animation after element is in DOM
                    setTimeout(() => {
                        clientSection.style.opacity = '1';
                        clientSection.style.transform = 'translateX(0)';
                    }, 10);
                }
            });
        }
        
        function extractClientIPFromElement(element) {
            // Extract client IP from element ID, handling IPv4 and IPv6
            const id = element.id;
            if (id.startsWith('client-')) {
                const ipPart = id.replace('client-', '');
                // Handle IPv4 (periods replaced with underscores)
                if (ipPart.match(/^\d+_\d+_\d+_\d+$/)) {
                    return ipPart.replace(/_/g, '.');
                }
                // Handle IPv6 and complex cases - reconstruct from header text
                const header = element.querySelector('.client-header h3');
                if (header) {
                    return header.textContent.replace('📱 ', '');
                }
                return ipPart;
            }
            return '';
        }
        
        function findExistingClientElement(container, clientIP) {
            const cleanIP = clientIP.replace(/[.:]/g, '_');
            return container.querySelector('#client-' + cleanIP);
        }
        
        function updateClientSectionSmooth(element, client) {
            // Update header stats
            const headerRight = element.querySelector('.client-stats');
            if (headerRight) {
                const ruleCount = headerRight.querySelector('.client-badge');
                const lastActivity = headerRight.querySelector('.last-activity');
                
                if (ruleCount && ruleCount.textContent !== client.rule_count + ' rules') {
                    ruleCount.style.transition = 'all 0.3s ease';
                    ruleCount.style.transform = 'scale(1.2)';
                    ruleCount.style.background = '#28a745';
                    
                    setTimeout(() => {
                        ruleCount.textContent = client.rule_count + ' rules';
                        ruleCount.style.transform = 'scale(1)';
                        ruleCount.style.background = '#007acc';
                    }, 150);
                }
                
                if (lastActivity) {
                    lastActivity.textContent = 'Last activity: ' + new Date(client.last_updated).toLocaleString();
                }
            }
            
            // Update rules - for now, recreate rules content (could be further optimized)
            const rulesContainer = element.querySelector('.client-rules');
            if (rulesContainer) {
                rulesContainer.innerHTML = '';
                client.rules.forEach(rule => {
                    const ruleDiv = document.createElement('div');
                    ruleDiv.className = 'rule-row';
                    ruleDiv.style.opacity = '0';
                    ruleDiv.style.transform = 'translateY(-10px)';
                    ruleDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                    
                    const ruleInfo = document.createElement('div');
                    ruleInfo.className = 'rule-info';
                    ruleInfo.innerHTML = 
                        '<div class="rule-primary">' + rule.domain + ' → ' + rule.resolved_ip + '</div>' +
                        '<div class="rule-secondary">TTL: ' + rule.ttl + 's | Expires: ' + new Date(rule.expires_at).toLocaleString() + '</div>';
                    
                    const ruleActions = document.createElement('div');
                    ruleActions.className = 'rule-actions';
                    ruleActions.innerHTML = '<button class="delete-btn" onclick="deleteRule(\'' + rule.key + '\')">Delete</button>';
                    
                    ruleDiv.appendChild(ruleInfo);
                    ruleDiv.appendChild(ruleActions);
                    rulesContainer.appendChild(ruleDiv);
                    
                    // Animate rule appearance
                    setTimeout(() => {
                        ruleDiv.style.opacity = '1';
                        ruleDiv.style.transform = 'translateY(0)';
                    }, Math.random() * 200); // Stagger animations
                });
            }
        }
        
        async function loadTableView(showLoading = true) {
            try {
                // Load traditional flat rules
                const rulesResponse = await fetch('/api/rules');
                if (!rulesResponse.ok) {
                    throw new Error('Rules API failed: ' + rulesResponse.status + ' ' + rulesResponse.statusText);
                }
                const rules = await rulesResponse.json();
                
                const tbody = document.getElementById('rulesBody');
                
                if (rules.length === 0) {
                    if (showLoading || tbody.children.length === 0) {
                        tbody.innerHTML = '';
                        const row = document.createElement('tr');
                        row.innerHTML = '<td colspan="6" style="text-align: center; color: #666; font-style: italic; padding: 40px;">' +
                            'No firewall rules found. Rules will appear here after DNS queries are processed through dfirewall.' +
                            '</td>';
                        tbody.appendChild(row);
                    }
                } else {
                    updateTableViewSmooth(tbody, rules);
                }
                
                if (showLoading) {
                    document.getElementById('loading').style.display = 'none';
                }
                document.getElementById('rulesTable').style.display = 'table';
            } catch (error) {
                if (!showLoading) {
                    // Silent failure for auto-refresh
                    console.warn('Table view update failed:', error.message);
                    return;
                }
                throw error; // Re-throw for manual refresh to show error
            }
        }
        
        function updateTableViewSmooth(tbody, newRules) {
            const existingRows = Array.from(tbody.querySelectorAll('tr[data-rule-key]'));
            const newRuleKeys = new Set(newRules.map(rule => rule.key));
            
            // Remove rows that no longer exist
            existingRows.forEach(row => {
                const ruleKey = row.getAttribute('data-rule-key');
                if (!newRuleKeys.has(ruleKey)) {
                    row.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    row.style.opacity = '0';
                    row.style.transform = 'translateX(-20px)';
                    setTimeout(() => row.remove(), 500);
                }
            });
            
            // Track existing rule keys for updates
            const existingRuleKeys = new Set(existingRows.map(row => row.getAttribute('data-rule-key')));
            
            // Clear tbody if empty state was showing
            if (tbody.querySelector('td[colspan="6"]')) {
                tbody.innerHTML = '';
            }
            
            // Add or update rules
            newRules.forEach((rule, index) => {
                const existingRow = tbody.querySelector('tr[data-rule-key="' + rule.key + '"]');
                
                if (existingRow) {
                    // Update existing row content (could be more granular)
                    const cells = existingRow.querySelectorAll('td');
                    if (cells.length >= 6) {
                        cells[3].textContent = rule.ttl; // Update TTL
                        cells[4].textContent = new Date(rule.expires_at).toLocaleString(); // Update expiry
                        
                        // Flash effect for updated rows
                        existingRow.style.transition = 'background-color 0.5s ease';
                        existingRow.style.backgroundColor = '#d4edda';
                        setTimeout(() => {
                            existingRow.style.backgroundColor = '';
                        }, 1000);
                    }
                } else {
                    // Add new rule with animation
                    const row = document.createElement('tr');
                    row.setAttribute('data-rule-key', rule.key);
                    row.style.opacity = '0';
                    row.style.transform = 'translateY(-10px)';
                    row.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    
                    row.innerHTML = 
                        '<td>' + rule.client_ip + '</td>' +
                        '<td>' + rule.resolved_ip + '</td>' +
                        '<td class="domain">' + rule.domain + '</td>' +
                        '<td class="ttl">' + rule.ttl + '</td>' +
                        '<td>' + new Date(rule.expires_at).toLocaleString() + '</td>' +
                        '<td>' +
                            '<button class="delete-btn" onclick="deleteRule(\'' + rule.key + '\')">Delete</button>' +
                        '</td>';
                    
                    tbody.appendChild(row);
                    
                    // Animate new row appearance
                    setTimeout(() => {
                        row.style.opacity = '1';
                        row.style.transform = 'translateY(0)';
                    }, index * 50); // Stagger animations
                }
            });
        }
        
        function createClientSection(client) {
            const section = document.createElement('div');
            section.className = 'client-section collapsed';  // Start collapsed by default
            section.id = 'client-' + client.client_ip.replace(/[.:]/g, '_');
            
            // Create header
            const header = document.createElement('div');
            header.className = 'client-header';
            header.onclick = () => toggleClientSection(section);
            
            const headerLeft = document.createElement('div');
            headerLeft.innerHTML = '<h3>📱 ' + client.client_ip + '</h3>';
            
            const headerRight = document.createElement('div');
            headerRight.className = 'client-stats';
            headerRight.innerHTML = 
                '<span class="client-badge">' + client.rule_count + ' rules</span>' +
                '<span class="ttl-badge" style="background: #17a2b8; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin: 0 5px;">TTL+' + client.ttl_grace_period_seconds + 's</span>' +
                '<span class="last-activity">Last activity: ' + new Date(client.last_updated).toLocaleString() + '</span>' +
                '<span class="collapse-icon">▼</span>';
            
            header.appendChild(headerLeft);
            header.appendChild(headerRight);
            section.appendChild(header);
            
            // Create rules container
            const rulesContainer = document.createElement('div');
            rulesContainer.className = 'client-rules';
            
            client.rules.forEach(rule => {
                const ruleDiv = document.createElement('div');
                ruleDiv.className = 'rule-row';
                
                const ruleInfo = document.createElement('div');
                ruleInfo.className = 'rule-info';
                ruleInfo.innerHTML = 
                    '<div class="rule-primary">' + rule.domain + ' → ' + rule.resolved_ip + '</div>' +
                    '<div class="rule-secondary">TTL: ' + rule.ttl + 's | Expires: ' + new Date(rule.expires_at).toLocaleString() + '</div>';
                
                const ruleActions = document.createElement('div');
                ruleActions.className = 'rule-actions';
                ruleActions.innerHTML = '<button class="delete-btn" onclick="deleteRule(\'' + rule.key + '\')">Delete</button>';
                
                ruleDiv.appendChild(ruleInfo);
                ruleDiv.appendChild(ruleActions);
                rulesContainer.appendChild(ruleDiv);
            });
            
            section.appendChild(rulesContainer);
            return section;
        }
        
        function toggleClientSection(section) {
            section.classList.toggle('collapsed');
        }
        
        async function deleteRule(key) {
            try {
                const response = await fetch('/api/rules/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({key: key})
                });
                
                if (response.ok) {
                    // Smooth refresh without loading indicator
                    loadData(false);
                } else {
                    alert('Error deleting rule');
                }
            } catch (error) {
                alert('Error deleting rule: ' + error.message);
            }
        }
        
        // Blacklist management functions
        async function addIPToBlacklist() {
            const ip = document.getElementById('ipInput').value.trim();
            if (!ip) {
                alert('Please enter an IP address');
                return;
            }
            
            try {
                const response = await fetch('/api/blacklist/ip/add', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ip: ip})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    alert('IP ' + result.ip + ' added to blacklist');
                    document.getElementById('ipInput').value = '';
                    loadBlacklists(); // Refresh blacklist display
                    loadData(false); // Smooth refresh of main data
                } else {
                    const errorText = await response.text();
                    alert('Error adding IP to blacklist: ' + errorText);
                }
            } catch (error) {
                alert('Error adding IP to blacklist: ' + error.message);
            }
        }
        
        async function addDomainToBlacklist() {
            const domain = document.getElementById('domainInput').value.trim();
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            try {
                const response = await fetch('/api/blacklist/domain/add', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({domain: domain})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    alert('Domain ' + result.domain + ' added to blacklist');
                    document.getElementById('domainInput').value = '';
                    loadBlacklists(); // Refresh blacklist display
                    loadData(false); // Smooth refresh of main data
                } else {
                    const errorText = await response.text();
                    alert('Error adding domain to blacklist: ' + errorText);
                }
            } catch (error) {
                alert('Error adding domain to blacklist: ' + error.message);
            }
        }
        
        async function removeFromBlacklist(type, value) {
            const endpoint = type === 'ip' ? '/api/blacklist/ip/remove' : '/api/blacklist/domain/remove';
            const key = type === 'ip' ? 'ip' : 'domain';
            
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({[key]: value})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    alert(type.toUpperCase() + ' ' + value + ' removed from blacklist');
                    loadBlacklists(); // Refresh blacklist display
                    loadData(false); // Smooth refresh of main data
                } else {
                    const errorText = await response.text();
                    alert('Error removing from blacklist: ' + errorText);
                }
            } catch (error) {
                alert('Error removing from blacklist: ' + error.message);
            }
        }
        
        async function loadBlacklists() {
            try {
                const response = await fetch('/api/blacklist/list');
                const data = await response.json();
                
                let html = '<div style="margin-bottom: 15px;"><strong>Blocked IPs (' + data.ips.length + '):</strong><br>';
                if (data.ips.length === 0) {
                    html += '<em>No blocked IPs</em>';
                } else {
                    data.ips.forEach(ip => {
                        html += '<span style="display: inline-block; margin: 2px; padding: 2px 6px; background: #ffebee; border: 1px solid #f44336; border-radius: 3px; font-family: monospace;">' + 
                               ip + ' <button onclick="removeFromBlacklist(\'ip\', \'' + ip + '\')" style="background: #f44336; color: white; border: none; padding: 1px 4px; margin-left: 5px; border-radius: 2px; cursor: pointer; font-size: 10px;">×</button></span>';
                    });
                }
                html += '</div>';
                
                html += '<div><strong>Blocked Domains (' + data.domains.length + '):</strong><br>';
                if (data.domains.length === 0) {
                    html += '<em>No blocked domains</em>';
                } else {
                    data.domains.forEach(domain => {
                        html += '<span style="display: inline-block; margin: 2px; padding: 2px 6px; background: #fff3e0; border: 1px solid #ff9800; border-radius: 3px; font-family: monospace;">' + 
                               domain + ' <button onclick="removeFromBlacklist(\'domain\', \'' + domain + '\')" style="background: #ff9800; color: white; border: none; padding: 1px 4px; margin-left: 5px; border-radius: 2px; cursor: pointer; font-size: 10px;">×</button></span>';
                    });
                }
                html += '</div>';
                
                document.getElementById('blacklistData').innerHTML = html;
            } catch (error) {
                document.getElementById('blacklistData').innerHTML = '<em style="color: #dc3545;">Error loading blacklists: ' + error.message + '</em>';
            }
        }
        
        // Reputation and AI analysis functions
        async function checkReputation() {
            const target = document.getElementById('analyzeInput').value.trim();
            const type = document.getElementById('analyzeType').value;
            
            if (!target) {
                alert('Please enter a target to analyze');
                return;
            }
            
            const resultsDiv = document.getElementById('analysisResults');
            resultsDiv.innerHTML = '<div style="color: #007acc;"><strong>🛡️ Checking reputation...</strong></div>';
            
            try {
                const response = await fetch('/api/reputation/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({target: target, type: type})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    displayReputationResult(result);
                } else {
                    const errorText = await response.text();
                    resultsDiv.innerHTML = '<div style="color: #dc3545;"><strong>❌ Reputation Check Error:</strong> ' + errorText + '</div>';
                }
            } catch (error) {
                resultsDiv.innerHTML = '<div style="color: #dc3545;"><strong>❌ Network Error:</strong> ' + error.message + '</div>';
            }
        }
        
        async function analyzeWithAI() {
            const target = document.getElementById('analyzeInput').value.trim();
            const type = document.getElementById('analyzeType').value;
            
            if (!target) {
                alert('Please enter a target to analyze');
                return;
            }
            
            const resultsDiv = document.getElementById('analysisResults');
            resultsDiv.innerHTML = '<div style="color: #17a2b8;"><strong>🤖 AI Analysis in progress...</strong></div>';
            
            try {
                const response = await fetch('/api/ai/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({target: target, type: type})
                });
                
                if (response.ok) {
                    const result = await response.json();
                    displayAIResult(result);
                } else {
                    const errorText = await response.text();
                    resultsDiv.innerHTML = '<div style="color: #dc3545;"><strong>❌ AI Analysis Error:</strong> ' + errorText + '</div>';
                }
            } catch (error) {
                resultsDiv.innerHTML = '<div style="color: #dc3545;"><strong>❌ Network Error:</strong> ' + error.message + '</div>';
            }
        }
        
        function displayReputationResult(result) {
            const resultsDiv = document.getElementById('analysisResults');
            const timestamp = new Date(result.checked_at).toLocaleString();
            const threatColor = result.is_threat ? '#dc3545' : '#28a745';
            const threatIcon = result.is_threat ? '⚠️' : '✅';
            const cacheIcon = result.cache_hit ? '💾 ' : '🌐 ';
            
            let html = 
                '<div style="border-left: 4px solid ' + threatColor + '; padding-left: 15px; margin-bottom: 15px;">' +
                    '<h4 style="margin: 0 0 10px 0; color: ' + threatColor + ';">' + threatIcon + ' Reputation Analysis</h4>' +
                    '<div style="font-family: monospace; background: white; padding: 10px; border-radius: 3px; margin-bottom: 10px;">' +
                        '<strong>Target:</strong> ' + result.target + '<br>' +
                        '<strong>Threat Score:</strong> ' + result.threat_score.toFixed(2) + '<br>' +
                        '<strong>Is Threat:</strong> ' + (result.is_threat ? 'YES' : 'NO') + '<br>' +
                        '<strong>Cache Hit:</strong> ' + cacheIcon + (result.cache_hit ? 'YES' : 'NO') + '<br>' +
                        '<strong>Timestamp:</strong> ' + timestamp +
                    '</div>';
            
            if (result.sources && result.sources.length > 0) {
                html += '<div style="margin-top: 10px;"><strong>Sources:</strong><ul>';
                result.sources.forEach(source => {
                    html += '<li>' + source + '</li>';
                });
                html += '</ul></div>';
            }
            
            html += '</div>';
            resultsDiv.innerHTML = html;
        }
        
        function displayAIResult(result) {
            const resultsDiv = document.getElementById('analysisResults');
            const timestamp = new Date(result.timestamp).toLocaleString();
            const threatColor = result.is_malicious ? '#dc3545' : (result.threat_score > 0.7 ? '#ffc107' : '#28a745');
            const threatIcon = result.is_malicious ? '🚨' : (result.threat_score > 0.7 ? '⚠️' : '✅');
            const confidencePercent = (result.confidence * 100).toFixed(1);
            const threatPercent = (result.threat_score * 100).toFixed(1);
            
            let html = 
                '<div style="border-left: 4px solid ' + threatColor + '; padding-left: 15px; margin-bottom: 15px;">' +
                    '<h4 style="margin: 0 0 10px 0; color: ' + threatColor + ';">' + threatIcon + ' AI Analysis</h4>' +
                    '<div style="font-family: monospace; background: white; padding: 10px; border-radius: 3px; margin-bottom: 10px;">' +
                        '<strong>Target:</strong> ' + result.target + '<br>' +
                        '<strong>Request ID:</strong> ' + result.request_id + '<br>' +
                        '<strong>Threat Score:</strong> ' + threatPercent + '%<br>' +
                        '<strong>Confidence:</strong> ' + confidencePercent + '%<br>' +
                        '<strong>Malicious:</strong> ' + (result.is_malicious ? 'YES' : 'NO') + '<br>' +
                        '<strong>Anomaly:</strong> ' + (result.is_anomaly ? 'YES' : 'NO') + '<br>' +
                        '<strong>Provider:</strong> ' + result.provider + '<br>' +
                        '<strong>Timestamp:</strong> ' + timestamp +
                    '</div>';
            
            if (result.reasoning && result.reasoning.trim() !== '') {
                html += 
                    '<div style="margin-top: 10px; background: #fff; padding: 10px; border-radius: 3px; border: 1px solid #ddd;">' +
                        '<strong>AI Reasoning:</strong><br>' +
                        '<div style="margin-top: 5px; font-style: italic; line-height: 1.4;">' +
                            result.reasoning +
                        '</div>' +
                    '</div>';
            }
            
            if (result.categories && result.categories.length > 0) {
                html += '<div style="margin-top: 10px;"><strong>Threat Categories:</strong><br>';
                result.categories.forEach(category => {
                    html += '<span style="display: inline-block; margin: 2px; padding: 2px 6px; background: #ffebee; border: 1px solid #f44336; border-radius: 3px; font-size: 12px;">' + category + '</span>';
                });
                html += '</div>';
            }
            
            html += '</div>';
            resultsDiv.innerHTML = html;
        }
        
        // Auto-detect target type based on input
        document.getElementById('analyzeInput').addEventListener('input', function() {
            const target = this.value.trim();
            const typeSelect = document.getElementById('analyzeType');
            
            // Simple heuristic to detect IP vs domain
            if (target.match(/^\\d{1,3}(\\.\\d{1,3}){3}$/) || target.match(/^[0-9a-fA-F:]+$/)) {
                typeSelect.value = 'ip';
            } else if (target.includes('.') && !target.match(/^\\d/)) {
                typeSelect.value = 'domain';
            }
        });
        
        // Check if user is authenticated (by trying to access a protected API)
        async function checkAuthStatus() {
            try {
                const response = await fetch('/api/health');
                if (response.ok) {
                    // User is authenticated, show auth status
                    const authStatusDiv = document.getElementById('authStatus');
                    const currentUserSpan = document.getElementById('currentUser');
                    
                    // Try to get username from response headers
                    const username = response.headers.get('X-Authenticated-User') || 'User';
                    currentUserSpan.textContent = username;
                    authStatusDiv.style.display = 'block';
                }
            } catch (error) {
                // User is not authenticated or error occurred
                console.log('Not authenticated or error checking auth status');
            }
        }
        
        // Settings management functions
        function toggleSettings() {
            const panel = document.getElementById('settingsPanel');
            if (panel.style.display === 'none' || panel.style.display === '') {
                panel.style.display = 'block';
                updateNextRefreshDisplay();
            } else {
                panel.style.display = 'none';
            }
        }
        
        function updateRefreshRate() {
            const selectElement = document.getElementById('refreshRate');
            refreshInterval = parseInt(selectElement.value);
            
            // Save to localStorage
            localStorage.setItem('dfirewall_refresh_interval', refreshInterval.toString());
            
            // Clear existing timers
            if (refreshTimer) {
                clearInterval(refreshTimer);
                refreshTimer = null;
            }
            if (countdownTimer) {
                clearInterval(countdownTimer);
                countdownTimer = null;
            }
            
            // Update status display
            updateRefreshStatus();
            
            // Start new timer if not disabled
            if (refreshInterval > 0) {
                startAutoRefresh();
            }
        }
        
        function updateRefreshStatus() {
            const statusElement = document.getElementById('refreshStatus');
            const nextRefreshElement = document.getElementById('nextRefresh');
            
            if (refreshInterval === 0) {
                statusElement.textContent = 'Disabled';
                statusElement.style.background = '#6c757d';
                statusElement.style.color = 'white';
                nextRefreshElement.textContent = 'Manual only';
            } else {
                const seconds = refreshInterval / 1000;
                const timeText = seconds >= 60 ? (seconds / 60) + 'm' : seconds + 's';
                statusElement.textContent = 'Active (' + timeText + ')';
                statusElement.style.background = '#28a745';
                statusElement.style.color = 'white';
                updateNextRefreshDisplay();
            }
        }
        
        function updateNextRefreshDisplay() {
            const nextRefreshElement = document.getElementById('nextRefresh');
            
            if (refreshInterval === 0 || !nextRefreshTime) {
                nextRefreshElement.textContent = 'Manual only';
                return;
            }
            
            const now = new Date();
            const timeUntilRefresh = Math.max(0, nextRefreshTime - now.getTime());
            const secondsUntilRefresh = Math.ceil(timeUntilRefresh / 1000);
            
            if (secondsUntilRefresh <= 0) {
                nextRefreshElement.textContent = 'Refreshing...';
            } else {
                nextRefreshElement.textContent = secondsUntilRefresh + 's';
            }
        }
        
        function startAutoRefresh() {
            if (refreshInterval === 0) return;
            
            nextRefreshTime = new Date().getTime() + refreshInterval;
            
            refreshTimer = setInterval(() => {
                loadData(false);
                nextRefreshTime = new Date().getTime() + refreshInterval;
            }, refreshInterval);
            
            // Update countdown every second
            if (countdownTimer) {
                clearInterval(countdownTimer);
            }
            countdownTimer = setInterval(updateNextRefreshDisplay, 1000);
        }
        
        function loadUserPreferences() {
            // Load refresh interval from localStorage
            const savedInterval = localStorage.getItem('dfirewall_refresh_interval');
            if (savedInterval) {
                refreshInterval = parseInt(savedInterval);
                document.getElementById('refreshRate').value = refreshInterval.toString();
            }
            
            updateRefreshStatus();
        }
        
        // Client History Functions
        function toggleClientHistory() {
            const panel = document.getElementById('clientHistoryPanel');
            if (panel.style.display === 'none' || panel.style.display === '') {
                panel.style.display = 'block';
            } else {
                panel.style.display = 'none';
                // Clear results when closing
                document.getElementById('historyResults').style.display = 'none';
                document.getElementById('historyError').style.display = 'none';
            }
        }
        
        async function loadClientHistory() {
            const clientIP = document.getElementById('clientIPInput').value.trim();
            const days = document.getElementById('historyDays').value;
            const limit = document.getElementById('historyLimit').value;
            
            // Validate client IP
            if (!clientIP) {
                showHistoryError('Please enter a client IP address');
                return;
            }
            
            // Simple IP validation
            const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
            if (!ipRegex.test(clientIP)) {
                showHistoryError('Please enter a valid IPv4 address');
                return;
            }
            
            // Show loading
            document.getElementById('historyLoading').style.display = 'block';
            document.getElementById('historyResults').style.display = 'none';
            document.getElementById('historyError').style.display = 'none';
            
            try {
                // Calculate time range
                const endTime = new Date();
                const startTime = new Date();
                startTime.setDate(endTime.getDate() - parseInt(days));
                
                // Build query URL
                const params = new URLSearchParams({
                    start: startTime.toISOString(),
                    end: endTime.toISOString(),
                    limit: limit
                });
                
                const response = await fetch('/api/client/history/' + encodeURIComponent(clientIP) + '?' + params);
                
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                
                const data = await response.json();
                displayClientHistory(data);
                
            } catch (error) {
                console.error('Error loading client history:', error);
                showHistoryError('Failed to load client history: ' + error.message);
            } finally {
                document.getElementById('historyLoading').style.display = 'none';
            }
        }
        
        function displayClientHistory(data) {
            // Update statistics
            document.getElementById('historyCount').textContent = data.total_lookups;
            const startDate = new Date(data.start_time).toLocaleDateString();
            const endDate = new Date(data.end_time).toLocaleDateString();
            document.getElementById('historyPeriod').textContent = startDate + ' to ' + endDate;
            
            // Clear and populate table
            const tbody = document.getElementById('historyTableBody');
            tbody.innerHTML = '';
            
            if (data.lookups && data.lookups.length > 0) {
                data.lookups.forEach(lookup => {
                    const row = document.createElement('tr');
                    
                    // Format timestamp
                    const timestamp = new Date(lookup.timestamp).toLocaleString();
                    
                    // Format TTL
                    const ttl = lookup.ttl ? lookup.ttl + 's' : '-';
                    
                    row.innerHTML = '<td style="font-family: monospace; font-size: 12px;">' + timestamp + '</td>' +
                        '<td style="word-break: break-all; max-width: 200px;">' + escapeHtml(lookup.domain) + '</td>' +
                        '<td style="font-family: monospace;">' + escapeHtml(lookup.resolved_ip) + '</td>' +
                        '<td style="font-family: monospace; text-align: right;">' + ttl + '</td>';
                    
                    tbody.appendChild(row);
                });
            } else {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="4" style="text-align: center; color: #666; padding: 20px;">No historical lookups found for this client</td>';
                tbody.appendChild(row);
            }
            
            // Show results
            document.getElementById('historyResults').style.display = 'block';
        }
        
        function showHistoryError(message) {
            document.getElementById('historyError').textContent = message;
            document.getElementById('historyError').style.display = 'block';
            document.getElementById('historyResults').style.display = 'none';
            document.getElementById('historyLoading').style.display = 'none';
        }
        
        // All Clients Functions
        function toggleAllClients() {
            const panel = document.getElementById('allClientsPanel');
            if (panel.style.display === 'none' || panel.style.display === '') {
                panel.style.display = 'block';
            } else {
                panel.style.display = 'none';
                // Clear results when closing
                document.getElementById('allClientsResults').style.display = 'none';
                document.getElementById('allClientsError').style.display = 'none';
            }
        }
        
        async function loadAllClients() {
            document.getElementById('allClientsLoading').style.display = 'block';
            document.getElementById('allClientsResults').style.display = 'none';
            document.getElementById('allClientsError').style.display = 'none';
            
            try {
                const response = await fetch('/api/clients');
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                
                const data = await response.json();
                displayAllClients(data);
                
            } catch (error) {
                console.error('Error loading all clients:', error);
                showAllClientsError('Failed to load clients: ' + error.message);
            } finally {
                document.getElementById('allClientsLoading').style.display = 'none';
            }
        }
        
        function displayAllClients(data) {
            // Update count
            document.getElementById('allClientsCount').textContent = 'Total: ' + data.total_clients + ' clients';
            
            // Clear and populate table
            const tbody = document.getElementById('allClientsTableBody');
            tbody.innerHTML = '';
            
            if (data.clients && data.clients.length > 0) {
                data.clients.forEach(client => {
                    const row = document.createElement('tr');
                    
                    // Format timestamps
                    const firstSeen = client.first_seen ? new Date(client.first_seen).toLocaleString() : '-';
                    const lastSeen = client.last_seen ? new Date(client.last_seen).toLocaleString() : '-';
                    
                    // Action buttons
                    const actions = '<button onclick="viewClientHistory(\'' + client.client_ip + '\')" style="background: #007acc; color: white; border: none; padding: 4px 8px; border-radius: 3px; cursor: pointer; margin-right: 5px; font-size: 12px;">📊 History</button>';
                    
                    row.innerHTML = '<td style="font-family: monospace;">' + escapeHtml(client.client_ip) + '</td>' +
                        '<td style="font-family: monospace; font-size: 12px;">' + firstSeen + '</td>' +
                        '<td style="font-family: monospace; font-size: 12px;">' + lastSeen + '</td>' +
                        '<td style="text-align: right;">' + client.total_lookups.toLocaleString() + '</td>' +
                        '<td style="text-align: right;">' + (client.active_rule_count || 0) + '</td>' +
                        '<td>' + actions + '</td>';
                    
                    tbody.appendChild(row);
                });
            } else {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="6" style="text-align: center; color: #666; padding: 20px;">No clients found</td>';
                tbody.appendChild(row);
            }
            
            // Show results
            document.getElementById('allClientsResults').style.display = 'block';
        }
        
        function showAllClientsError(message) {
            document.getElementById('allClientsError').textContent = message;
            document.getElementById('allClientsError').style.display = 'block';
            document.getElementById('allClientsResults').style.display = 'none';
            document.getElementById('allClientsLoading').style.display = 'none';
        }
        
        function viewClientHistory(clientIP) {
            // Show the client history panel
            const historyPanel = document.getElementById('clientHistoryPanel');
            historyPanel.style.display = 'block';
            
            // Fill in the client IP and load history
            document.getElementById('clientIPInput').value = clientIP;
            loadClientHistory();
            
            // Scroll to history panel
            historyPanel.scrollIntoView({ behavior: 'smooth' });
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Security panel management functions
        function toggleSecurityPanel() {
            const panel = document.getElementById('securityPanel');
            if (panel.style.display === 'none' || panel.style.display === '') {
                panel.style.display = 'block';
                // Load blacklists when opening panel for the first time
                loadBlacklists();
            } else {
                panel.style.display = 'none';
            }
        }
        
        function switchSecurityTab(tabName) {
            // Hide all security tab panels
            const panels = document.querySelectorAll('#securityPanel .tab-panel');
            panels.forEach(panel => {
                panel.classList.remove('active');
            });
            
            // Remove active class from all security tab buttons
            const buttons = document.querySelectorAll('#securityPanel .tab-btn');
            buttons.forEach(button => {
                button.classList.remove('active');
            });
            
            // Show the selected tab panel
            const selectedPanel = document.getElementById(tabName + 'SecurityTab');
            if (selectedPanel) {
                selectedPanel.classList.add('active');
            }
            
            // Add active class to the clicked button
            event.target.classList.add('active');
            
            // Load data specific to the tab if needed
            if (tabName === 'blacklist') {
                loadBlacklists();
            }
        }
        
        // Load data on page load
        window.onload = function() {
            checkAuthStatus();
            loadUserPreferences();
            loadData();
            loadBlacklists();
            
            // Start auto-refresh if enabled
            if (refreshInterval > 0) {
                startAutoRefresh();
            }
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlTemplate))
}

// isRateLimited checks if the client IP has exceeded the rate limit
func (rl *rateLimiter) isRateLimited(clientIP string, isLogin bool) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	// Choose the appropriate map and limit based on request type
	var clientMap map[string]*requestRecord
	var maxRequests int
	
	if isLogin {
		clientMap = rl.logins
		maxRequests = maxLoginAttempts
	} else {
		clientMap = rl.clients
		maxRequests = maxRequestsPerMinute
	}
	
	now := time.Now()
	record, exists := clientMap[clientIP]
	
	if !exists {
		// First request from this IP
		clientMap[clientIP] = &requestRecord{
			count:     1,
			lastReset: now,
		}
		return false
	}
	
	// Check if we need to reset the window
	if now.Sub(record.lastReset) >= time.Duration(rateWindowMinutes)*time.Minute {
		record.count = 1
		record.lastReset = now
		return false
	}
	
	// Increment count and check limit
	record.count++
	return record.count > maxRequests
}

// cleanupOldRecords removes old rate limiting records (call periodically)
func (rl *rateLimiter) cleanupOldRecords() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := time.Duration(rateWindowMinutes*2) * time.Minute // Keep records for 2 windows
	
	// Clean up general request records
	for ip, record := range rl.clients {
		if now.Sub(record.lastReset) > cutoff {
			delete(rl.clients, ip)
		}
	}
	
	// Clean up login attempt records  
	for ip, record := range rl.logins {
		if now.Sub(record.lastReset) > cutoff {
			delete(rl.logins, ip)
		}
	}
}

// rateLimitMiddleware provides rate limiting for HTTP requests
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		
		// Check if this is a login request
		isLogin := r.URL.Path == "/login" && r.Method == "POST"
		
		if globalRateLimiter.isRateLimited(clientIP, isLogin) {
			if isLogin {
				log.Printf("Login rate limit exceeded for IP: %s", clientIP)
				http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
			} else {
				log.Printf("Rate limit exceeded for IP: %s", clientIP)
				http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
			}
			return
		}
		
		next(w, r)
	}
}

// startRateLimitCleanup starts a goroutine to periodically clean up old rate limit records
func startRateLimitCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				globalRateLimiter.cleanupOldRecords()
			}
		}
	}()
}