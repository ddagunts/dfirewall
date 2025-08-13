package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Rule struct {
	ClientIP   string `json:"client_ip"`
	ResolvedIP string `json:"resolved_ip"`
	Domain     string `json:"domain"`
	TTL        string `json:"ttl"`
	ExpiresAt  string `json:"expires_at"`
	RecordType string `json:"record_type"`
}

type ClientRules struct {
	ClientIP       string   `json:"client_ip"`
	Rules          []Rule   `json:"rules"`
	BlockedDomains []string `json:"blocked_domains"`
}

type HistoricalRuleWeb struct {
	ClientIP    string `json:"client_ip"`
	ResolvedIP  string `json:"resolved_ip"`
	Domain      string `json:"domain"`
	RecordType  string `json:"record_type"`
	Action      string `json:"action"`
	Timestamp   int64  `json:"timestamp"`
	TTL         string `json:"ttl,omitempty"`
	FormattedTime string `json:"formatted_time"`
}

func setupWebUI(redisClient *redis.Client) {
	webPort := 8080
	webPortEnv := os.Getenv("WEB_PORT")
	if value, err := strconv.Atoi(webPortEnv); err == nil {
		webPort = value
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		apiClientsHandler(w, r, redisClient)
	})
	http.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request) {
		apiRulesHandler(w, r, redisClient)
	})
	http.HandleFunc("/client/", func(w http.ResponseWriter, r *http.Request) {
		clientHandler(w, r, redisClient)
	})
	http.HandleFunc("/api/blocked-domains/", func(w http.ResponseWriter, r *http.Request) {
		apiBlockedDomainsHandler(w, r, redisClient)
	})
	http.HandleFunc("/api/history/", func(w http.ResponseWriter, r *http.Request) {
		apiHistoryHandler(w, r, redisClient)
	})

	log.Printf("Web UI started on http://localhost:%d", webPort)
	go func() {
		if err := http.ListenAndServe(":"+strconv.Itoa(webPort), nil); err != nil {
			log.Printf("Web UI server error: %v", err)
		}
	}()
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>dfirewall - DNS Firewall Rules</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; color: #333; }
        .clients-grid { display: grid; gap: 15px; }
        .client-card { border: 1px solid #ddd; padding: 15px; border-radius: 6px; background: #fafafa; }
        .client-ip { font-weight: bold; color: #2c3e50; font-size: 16px; }
        .rule-count { color: #7f8c8d; font-size: 14px; margin-top: 5px; }
        .view-rules { display: inline-block; margin-top: 10px; padding: 6px 12px; background: #3498db; color: white; text-decoration: none; border-radius: 4px; font-size: 14px; }
        .view-rules:hover { background: #2980b9; }
        .loading { text-align: center; color: #7f8c8d; }
        .error { color: #e74c3c; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>dfirewall</h1>
            <p>DNS Firewall Rules Dashboard</p>
        </div>
        
        <div id="clients-container">
            <div class="loading">Loading clients...</div>
        </div>
    </div>

    <script>
        async function loadClients() {
            try {
                const response = await fetch('/api/clients');
                const clients = await response.json();
                
                const container = document.getElementById('clients-container');
                
                if (clients.length === 0) {
                    container.innerHTML = '<div class="error">No clients found</div>';
                    return;
                }
                
                const html = clients.map(client => {
                    return ` + "`" + `
                        <div class="client-card">
                            <div class="client-ip">${client.client_ip}</div>
                            <div class="rule-count">${client.rules.length} rules, ${client.blocked_domains ? client.blocked_domains.length : 0} blocked domains</div>
                            <a href="/client/${client.client_ip}" class="view-rules">View Rules</a>
                        </div>
                    ` + "`" + `;
                }).join('');
                
                container.innerHTML = ` + "`" + `<div class="clients-grid">${html}</div>` + "`" + `;
            } catch (error) {
                document.getElementById('clients-container').innerHTML = 
                    ` + "`" + `<div class="error">Error loading clients: ${error.message}</div>` + "`" + `;
            }
        }
        
        loadClients();
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, tmpl)
}

func clientHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	clientIP := strings.TrimPrefix(r.URL.Path, "/client/")
	if clientIP == "" {
		http.Error(w, "Client IP required", http.StatusBadRequest)
		return
	}

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>dfirewall - Rules for {{.ClientIP}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; color: #333; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #3498db; text-decoration: none; }
        .back-link:hover { text-decoration: underline; }
        .rules-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .rules-table th, .rules-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .rules-table th { background-color: #f8f9fa; font-weight: bold; color: #2c3e50; }
        .rules-table tr:hover { background-color: #f5f5f5; }
        .domain { font-family: monospace; }
        .ip { font-family: monospace; color: #27ae60; }
        .record-type { font-weight: bold; color: #3498db; }
        .ttl { color: #8e44ad; }
        .loading { text-align: center; color: #7f8c8d; }
        .error { color: #e74c3c; text-align: center; }
        .no-rules { text-align: center; color: #7f8c8d; padding: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; margin-bottom: 20px; }
        .add-domain { margin: 20px 0; display: flex; gap: 10px; }
        .add-domain input { flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; }
        .add-btn { padding: 8px 16px; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .add-btn:hover { background: #229954; }
        .blocked-domain-item { display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #f8f9fa; border-radius: 4px; margin-bottom: 5px; }
        .blocked-domain-name { font-family: monospace; color: #e74c3c; }
        .remove-btn { background: #dc3545; color: white; border: none; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px; }
        .remove-btn:hover { background: #c82333; }
        .time-filter { margin-bottom: 20px; }
        .time-filter label { margin-right: 10px; font-weight: bold; }
        .time-filter select { padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; }
        .timezone-selector { margin-bottom: 20px; }
        .timezone-selector label { margin-right: 10px; font-weight: bold; }
        .timezone-selector select { padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; }
        .history-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .history-table th, .history-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }
        .history-table th { background-color: #f8f9fa; font-weight: bold; color: #2c3e50; }
        .history-table tr:hover { background-color: #f5f5f5; }
        .action-created { color: #27ae60; font-weight: bold; }
        .action-updated { color: #3498db; font-weight: bold; }
        .action-blocked { color: #e74c3c; font-weight: bold; }
        .action-unblocked { color: #f39c12; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">&lt; Back to All Clients</a>
        
        <div class="header">
            <h1>Rules for {{.ClientIP}}</h1>
        </div>
        
        <div class="timezone-selector">
            <label for="timezone-select">Display times in:</label>
            <select id="timezone-select" onchange="updateTimezoneDisplay()">
                <option value="UTC">UTC</option>
                <option value="local" selected>Local Time</option>
            </select>
        </div>
        
        <div class="section">
            <h2>Blocked Domains</h2>
            <div id="blocked-domains-container">
                <div class="loading">Loading blocked domains...</div>
            </div>
            <div class="add-domain">
                <input type="text" id="domain-input" placeholder="Enter domain to block (e.g., example.com)">
                <button onclick="addBlockedDomain()" class="add-btn">Block Domain</button>
            </div>
        </div>
        
        <div class="section">
            <h2>DNS Rules</h2>
            <div id="rules-container">
                <div class="loading">Loading rules...</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Historical Rules</h2>
            <div class="time-filter">
                <label for="time-filter-select">Show history for last:</label>
                <select id="time-filter-select" onchange="loadHistoryWithFilter()">
                    <option value="1">1 hour</option>
                    <option value="6">6 hours</option>
                    <option value="24" selected>24 hours</option>
                    <option value="72">3 days</option>
                    <option value="168">1 week</option>
                    <option value="720">30 days</option>
                </select>
            </div>
            <div id="history-container">
                <div class="loading">Loading history...</div>
            </div>
        </div>
    </div>

    <script>
        let currentTimezone = 'local'; // Default to local time
        
        function formatTimeWithTimezone(timeString, timezone) {
            // Parse the server time (assume UTC format: YYYY-MM-DD HH:MM:SS)
            const serverTime = new Date(timeString + ' UTC');
            
            if (timezone === 'UTC') {
                return serverTime.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
            } else {
                // Local time
                return serverTime.toLocaleString() + ' (Local)';
            }
        }
        
        function updateTimezoneDisplay() {
            currentTimezone = document.getElementById('timezone-select').value;
            loadRules();
            loadHistoryWithFilter();
        }
        
        async function loadRules() {
            try {
                const response = await fetch('/api/rules/{{.ClientIP}}');
                const rules = await response.json();
                
                const container = document.getElementById('rules-container');
                
                if (rules.length === 0) {
                    container.innerHTML = '<div class="no-rules">No rules found for this client</div>';
                    return;
                }
                
                const tableRows = rules.map(rule => {
                    const formattedTime = formatTimeWithTimezone(rule.expires_at, currentTimezone);
                    return ` + "`" + `
                        <tr>
                            <td class="domain">${rule.domain}</td>
                            <td class="ip">${rule.resolved_ip}</td>
                            <td class="record-type">${rule.record_type}</td>
                            <td class="ttl">${rule.ttl}s</td>
                            <td>${formattedTime}</td>
                        </tr>
                    ` + "`" + `;
                }).join('');
                
                container.innerHTML = ` + "`" + `
                    <table class="rules-table">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Resolved IP</th>
                                <th>Type</th>
                                <th>TTL</th>
                                <th>Expires At</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${tableRows}
                        </tbody>
                    </table>
                ` + "`" + `;
            } catch (error) {
                document.getElementById('rules-container').innerHTML = 
                    ` + "`" + `<div class="error">Error loading rules: ${error.message}</div>` + "`" + `;
            }
        }
        
        loadRules();
        loadBlockedDomains();
        loadHistoryWithFilter();
        
        async function loadBlockedDomains() {
            try {
                const response = await fetch('/api/blocked-domains/{{.ClientIP}}');
                const blockedDomains = await response.json();
                
                const container = document.getElementById('blocked-domains-container');
                
                if (blockedDomains.length === 0) {
                    container.innerHTML = '<div class="no-rules">No blocked domains for this client</div>';
                    return;
                }
                
                const html = blockedDomains.map(domain => {
                    return ` + "`" + `
                        <div class="blocked-domain-item">
                            <span class="blocked-domain-name">${domain}</span>
                            <button class="remove-btn" onclick="removeBlockedDomain('${domain}')">Remove</button>
                        </div>
                    ` + "`" + `;
                }).join('');
                
                container.innerHTML = html;
            } catch (error) {
                document.getElementById('blocked-domains-container').innerHTML = 
                    ` + "`" + `<div class="error">Error loading blocked domains: ${error.message}</div>` + "`" + `;
            }
        }
        
        async function addBlockedDomain() {
            const domainInput = document.getElementById('domain-input');
            const domain = domainInput.value.trim();
            
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }
            
            try {
                const response = await fetch('/api/blocked-domains/{{.ClientIP}}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ domain: domain })
                });
                
                if (response.ok) {
                    domainInput.value = '';
                    loadBlockedDomains();
                } else {
                    const error = await response.text();
                    alert('Error adding domain: ' + error);
                }
            } catch (error) {
                alert('Error adding domain: ' + error.message);
            }
        }
        
        async function removeBlockedDomain(domain) {
            if (!confirm('Are you sure you want to unblock ' + domain + '?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/blocked-domains/{{.ClientIP}}', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ domain: domain })
                });
                
                if (response.ok) {
                    loadBlockedDomains();
                } else {
                    const error = await response.text();
                    alert('Error removing domain: ' + error);
                }
            } catch (error) {
                alert('Error removing domain: ' + error.message);
            }
        }
        
        async function loadHistoryWithFilter() {
            const hours = document.getElementById('time-filter-select').value;
            
            try {
                const response = await fetch('/api/history/{{.ClientIP}}?hours=' + hours);
                const history = await response.json();
                
                const container = document.getElementById('history-container');
                
                if (history.length === 0) {
                    container.innerHTML = '<div class="no-rules">No historical rules found for the selected time period</div>';
                    return;
                }
                
                const tableRows = history.map(rule => {
                    const actionClass = 'action-' + rule.action;
                    const formattedTime = formatTimeWithTimezone(rule.formatted_time, currentTimezone);
                    const resolvedIpCell = rule.resolved_ip ? 
                        ` + "`" + `<td class="ip">${rule.resolved_ip}</td>` + "`" + ` : 
                        '<td>-</td>';
                    const recordTypeCell = rule.record_type ? 
                        ` + "`" + `<td class="record-type">${rule.record_type}</td>` + "`" + ` :
                        '<td>-</td>';
                    const ttlCell = rule.ttl ? 
                        ` + "`" + `<td class="ttl">${rule.ttl}s</td>` + "`" + ` :
                        '<td>-</td>';
                    
                    return ` + "`" + `
                        <tr>
                            <td>${formattedTime}</td>
                            <td class="${actionClass}">${rule.action}</td>
                            <td class="domain">${rule.domain}</td>
                            ${resolvedIpCell}
                            ${recordTypeCell}
                            ${ttlCell}
                        </tr>
                    ` + "`" + `;
                }).join('');
                
                container.innerHTML = ` + "`" + `
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Action</th>
                                <th>Domain</th>
                                <th>Resolved IP</th>
                                <th>Type</th>
                                <th>TTL</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${tableRows}
                        </tbody>
                    </table>
                ` + "`" + `;
            } catch (error) {
                document.getElementById('history-container').innerHTML = 
                    ` + "`" + `<div class="error">Error loading history: ${error.message}</div>` + "`" + `;
            }
        }
    </script>
</body>
</html>`

	t, _ := template.New("client").Parse(tmpl)
	data := struct{ ClientIP string }{ClientIP: clientIP}
	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, data)
}

func apiClientsHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	ctx := context.Background()

	keys, err := redisClient.Keys(ctx, "rules|*").Result()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clientMap := make(map[string][]Rule)

	for _, key := range keys {
		parts := strings.Split(key, "|")
		if len(parts) < 4 || len(parts) > 5 {
			continue
		}

		clientIP := parts[1]
		resolvedIP := parts[2]
		domain := parts[3]
		recordType := "A" // default for backward compatibility
		if len(parts) == 5 {
			recordType = parts[4]
		}

		ttl, err := redisClient.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		rule := Rule{
			ClientIP:   clientIP,
			ResolvedIP: resolvedIP,
			Domain:     domain,
			TTL:        fmt.Sprintf("%.0f", ttl.Seconds()),
			ExpiresAt:  time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05"),
			RecordType: recordType,
		}

		clientMap[clientIP] = append(clientMap[clientIP], rule)
	}

	var clients []ClientRules
	for clientIP, rules := range clientMap {
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Domain < rules[j].Domain
		})
		
		// Get blocked domains for this client
		blockedDomains, _ := getBlockedDomainsFromRedis(ctx, redisClient, clientIP)
		
		clients = append(clients, ClientRules{
			ClientIP:       clientIP,
			Rules:          rules,
			BlockedDomains: blockedDomains,
		})
	}

	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ClientIP < clients[j].ClientIP
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func apiRulesHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	clientIP := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if clientIP == "" {
		http.Error(w, "Client IP required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	pattern := "rules|" + clientIP + "|*"
	keys, err := redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var rules []Rule

	for _, key := range keys {
		parts := strings.Split(key, "|")
		if len(parts) < 4 || len(parts) > 5 {
			continue
		}

		resolvedIP := parts[2]
		domain := parts[3]
		recordType := "A" // default for backward compatibility
		if len(parts) == 5 {
			recordType = parts[4]
		}

		ttl, err := redisClient.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		rule := Rule{
			ClientIP:   clientIP,
			ResolvedIP: resolvedIP,
			Domain:     domain,
			TTL:        fmt.Sprintf("%.0f", ttl.Seconds()),
			ExpiresAt:  time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05"),
			RecordType: recordType,
		}

		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Domain < rules[j].Domain
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func getBlockedDomainsFromRedis(ctx context.Context, redisClient *redis.Client, clientIP string) ([]string, error) {
	key := "blocked_domains|" + clientIP
	domains, err := redisClient.SMembers(ctx, key).Result()
	if err != nil && err != redis.Nil {
		return nil, err
	}
	sort.Strings(domains)
	return domains, nil
}

func addBlockedDomainToRedis(ctx context.Context, redisClient *redis.Client, clientIP, domain string) error {
	key := "blocked_domains|" + clientIP
	err := redisClient.SAdd(ctx, key, domain).Err()
	if err == nil {
		// Record historical domain blocking
		recordHistoricalRule(ctx, redisClient, clientIP, "", domain, "", "blocked", "")
	}
	return err
}

func removeBlockedDomainFromRedis(ctx context.Context, redisClient *redis.Client, clientIP, domain string) error {
	key := "blocked_domains|" + clientIP
	err := redisClient.SRem(ctx, key, domain).Err()
	if err == nil {
		// Record historical domain unblocking
		recordHistoricalRule(ctx, redisClient, clientIP, "", domain, "", "unblocked", "")
	}
	return err
}

func apiBlockedDomainsHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	clientIP := strings.TrimPrefix(r.URL.Path, "/api/blocked-domains/")
	if clientIP == "" {
		http.Error(w, "Client IP required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	switch r.Method {
	case "GET":
		domains, err := getBlockedDomainsFromRedis(ctx, redisClient, clientIP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(domains)

	case "POST":
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		domain := strings.TrimSpace(req.Domain)
		if domain == "" {
			http.Error(w, "Domain is required", http.StatusBadRequest)
			return
		}
		
		// Validate domain format
		domain = strings.TrimSuffix(domain, ".")
		if !isValidDomain(domain) {
			http.Error(w, "Invalid domain format", http.StatusBadRequest)
			return
		}
		
		if err := addBlockedDomainToRedis(ctx, redisClient, clientIP, domain); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Domain blocked successfully"))

	case "DELETE":
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		domain := strings.TrimSpace(req.Domain)
		if domain == "" {
			http.Error(w, "Domain is required", http.StatusBadRequest)
			return
		}
		
		if err := removeBlockedDomainFromRedis(ctx, redisClient, clientIP, domain); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Domain unblocked successfully"))

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
			if r == '-' && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}

func apiHistoryHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	clientIP := strings.TrimPrefix(r.URL.Path, "/api/history/")
	if clientIP == "" {
		http.Error(w, "Client IP required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// Get time filter parameters
	hoursParam := r.URL.Query().Get("hours")
	hours := 24 // default to last 24 hours
	if hoursParam != "" {
		if parsedHours, err := strconv.Atoi(hoursParam); err == nil && parsedHours > 0 {
			hours = parsedHours
		}
	}

	// Calculate timestamp threshold
	timeThreshold := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	// Get all history keys for this client
	pattern := "history|" + clientIP + "|*"
	keys, err := redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var historicalRules []HistoricalRuleWeb

	for _, key := range keys {
		// Extract timestamp from key to filter
		parts := strings.Split(key, "|")
		if len(parts) != 3 {
			continue
		}
		keyTimestamp, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || keyTimestamp < timeThreshold {
			continue
		}

		// Get the historical rule data
		data, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var historicalRule HistoricalRule
		if err := json.Unmarshal([]byte(data), &historicalRule); err != nil {
			continue
		}

		// Convert to web format
		webRule := HistoricalRuleWeb{
			ClientIP:      historicalRule.ClientIP,
			ResolvedIP:    historicalRule.ResolvedIP,
			Domain:        historicalRule.Domain,
			RecordType:    historicalRule.RecordType,
			Action:        historicalRule.Action,
			Timestamp:     historicalRule.Timestamp,
			TTL:           historicalRule.TTL,
			FormattedTime: time.Unix(historicalRule.Timestamp, 0).UTC().Format("2006-01-02 15:04:05"),
		}

		historicalRules = append(historicalRules, webRule)
	}

	// Sort by timestamp (newest first)
	sort.Slice(historicalRules, func(i, j int) bool {
		return historicalRules[i].Timestamp > historicalRules[j].Timestamp
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(historicalRules)
}