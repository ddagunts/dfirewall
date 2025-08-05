package main

import (
	"log"
	"net/http"
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
	
	log.Printf("Starting web UI server on port %s (HTTPS: %v, Auth: %v)", 
		port, authConfig.HTTPSEnabled, isAuthEnabled())
	
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
	
	server := &http.Server{
		Addr:    ":" + port,
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
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #007acc; color: white; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
        .stat-box h3 { margin: 0; font-size: 24px; }
        .stat-box p { margin: 5px 0 0 0; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:hover { background-color: #f9f9f9; }
        .delete-btn { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
        .delete-btn:hover { background: #c82333; }
        .refresh-btn { background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
        .refresh-btn:hover { background: #218838; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .error { color: #dc3545; text-align: center; padding: 20px; }
        .domain { word-break: break-all; max-width: 200px; }
        .ttl { font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>dfirewall - Firewall Rule Management</h1>
        
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
            <div>
                <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
                <a href="/api/docs" target="_blank" style="background: #6c757d; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin-left: 10px; display: inline-block;">📖 API Documentation</a>
            </div>
            <div id="authStatus" style="display: none;">
                <span style="color: #666; margin-right: 10px;">Logged in as: <strong id="currentUser">-</strong></span>
                <a href="/logout" style="background: #dc3545; color: white; text-decoration: none; padding: 8px 15px; border-radius: 3px; font-size: 14px;">🚪 Logout</a>
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
        
        <!-- Blacklist Management Section -->
        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #007acc;">
            <h2>Blacklist Management</h2>
            
            <div style="display: flex; gap: 20px; margin: 20px 0;">
                <div style="flex: 1;">
                    <h3>Add to Blacklist</h3>
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
                    <h3>Current Blacklists</h3>
                    <button onclick="loadBlacklists()" style="background: #17a2b8; color: white; border: none; padding: 8px 15px; border-radius: 3px; cursor: pointer; margin-bottom: 10px;">🔄 Refresh Blacklists</button>
                    <div id="blacklistData" style="font-size: 12px; max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 3px; background: #f8f9fa;"></div>
                </div>
            </div>
        </div>
        
        <!-- Reputation & AI Analysis Section -->
        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #007acc;">
            <h2>Reputation & AI Analysis</h2>
            
            <div style="display: flex; gap: 20px; margin: 20px 0;">
                <div style="flex: 1;">
                    <h3>Analyze Target</h3>
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

    <script>
        // ASSUMPTION: Use vanilla JavaScript to avoid external dependencies
        async function loadData() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('error').style.display = 'none';
            document.getElementById('rulesTable').style.display = 'none';
            
            try {
                // Load statistics
                const statsResponse = await fetch('/api/stats');
                if (!statsResponse.ok) {
                    throw new Error('Stats API failed: ' + statsResponse.status + ' ' + statsResponse.statusText);
                }
                const stats = await statsResponse.json();
                
                document.getElementById('totalRules').textContent = stats.total_rules;
                document.getElementById('activeClients').textContent = stats.active_clients;
                document.getElementById('uniqueDomains').textContent = stats.unique_domains;
                document.getElementById('uniqueIPs').textContent = stats.unique_ips;
                
                // Load rules
                const rulesResponse = await fetch('/api/rules');
                if (!rulesResponse.ok) {
                    throw new Error('Rules API failed: ' + rulesResponse.status + ' ' + rulesResponse.statusText);
                }
                const rules = await rulesResponse.json();
                
                const tbody = document.getElementById('rulesBody');
                tbody.innerHTML = '';
                
                if (rules.length === 0) {
                    // Show a message when no rules exist
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="6" style="text-align: center; color: #666; font-style: italic; padding: 40px;">' +
                        'No firewall rules found. Rules will appear here after DNS queries are processed through dfirewall.' +
                        '</td>';
                    tbody.appendChild(row);
                } else {
                    rules.forEach(rule => {
                        const row = document.createElement('tr');
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
                    });
                }
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('rulesTable').style.display = 'table';
                
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
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
                    loadData(); // Refresh the data
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
        
        // Load data on page load
        window.onload = function() {
            checkAuthStatus();
            loadData();
            loadBlacklists();
        };
        
        // Auto-refresh every 30 seconds
        setInterval(loadData, 30000);
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