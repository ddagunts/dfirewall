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
	ClientIP string `json:"client_ip"`
	Rules    []Rule `json:"rules"`
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
                            <div class="rule-count">${client.rules.length} rules</div>
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
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">&lt; Back to All Clients</a>
        
        <div class="header">
            <h1>Rules for {{.ClientIP}}</h1>
        </div>
        
        <div id="rules-container">
            <div class="loading">Loading rules...</div>
        </div>
    </div>

    <script>
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
                    return ` + "`" + `
                        <tr>
                            <td class="domain">${rule.domain}</td>
                            <td class="ip">${rule.resolved_ip}</td>
                            <td class="record-type">${rule.record_type}</td>
                            <td class="ttl">${rule.ttl}s</td>
                            <td>${rule.expires_at}</td>
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
			ExpiresAt:  time.Now().Add(ttl).Format("2006-01-02 15:04:05"),
			RecordType: recordType,
		}

		clientMap[clientIP] = append(clientMap[clientIP], rule)
	}

	var clients []ClientRules
	for clientIP, rules := range clientMap {
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Domain < rules[j].Domain
		})
		clients = append(clients, ClientRules{
			ClientIP: clientIP,
			Rules:    rules,
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
			ExpiresAt:  time.Now().Add(ttl).Format("2006-01-02 15:04:05"),
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