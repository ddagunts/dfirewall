package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type Route struct {
	Zone string
	From net.IP
	To   net.IP
}

// FirewallRule represents a single firewall rule from Redis
type FirewallRule struct {
	Key        string    `json:"key"`
	ClientIP   string    `json:"client_ip"`
	ResolvedIP string    `json:"resolved_ip"`
	Domain     string    `json:"domain"`
	TTL        int64     `json:"ttl"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// UIStats represents statistics for the web UI
type UIStats struct {
	TotalRules    int `json:"total_rules"`
	ActiveClients int `json:"active_clients"`
	UniqueDomains int `json:"unique_domains"`
	UniqueIPs     int `json:"unique_ips"`
}

// Input validation functions
var (
	validIPRegex     = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$`)
)

func validateIP(ip string) bool {
	if !validIPRegex.MatchString(ip) {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil
}

func validateDomain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	return validDomainRegex.MatchString(domain)
}

func validateTTL(ttl uint32) bool {
	return ttl > 0 && ttl <= 86400 // Max 24 hours
}

func validateInvokeScript(scriptPath string) error {
	if scriptPath == "" {
		return fmt.Errorf("script path is empty")
	}
	
	// Resolve to absolute path to prevent directory traversal
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return fmt.Errorf("invalid script path: %v", err)
	}
	
	// Check if file exists and is executable
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("script not found: %v", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("script path is a directory")
	}
	
	// Check if file is executable
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("script is not executable")
	}
	
	return nil
}

func sanitizeForShell(input string) string {
	// Remove any shell metacharacters
	return regexp.MustCompile(`[^a-zA-Z0-9\._\-]`).ReplaceAllString(input, "")
}

func inRange(ipLow, ipHigh, ip netip.Addr) bool {
	return ipLow.Compare(ip) <= 0 && ipHigh.Compare(ip) > 0
}

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

	opt, err := redis.ParseURL(redisEnv)
	if err != nil {
		panic(err)
	}

	redisClient := redis.NewClient(opt)

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
				
				// ASSUMPTION: Only process our firewall rule keys (format: "rules:client:ip:domain")
				if strings.HasPrefix(expiredKey, "rules:") {
					parts := strings.Split(expiredKey, ":")
					if len(parts) >= 4 {
						clientIP := parts[1]
						resolvedIP := parts[2]
						domain := strings.Join(parts[3:], ":") // domain might contain colons
						
						// QUESTION: Should we validate IPs here or trust Redis key format?
						// ASSUMPTION: Trust Redis key format since we control key creation
						
						log.Printf("Key expired: %s (client=%s, resolved=%s, domain=%s)", expiredKey, clientIP, resolvedIP, domain)
						
						// Set environment variables for the expire script
						// ASSUMPTION: Use same env vars as invoke script for consistency
						os.Setenv("CLIENT_IP", sanitizeForShell(clientIP))
						os.Setenv("RESOLVED_IP", sanitizeForShell(resolvedIP))
						os.Setenv("DOMAIN", sanitizeForShell(domain))
						os.Setenv("TTL", "0") // TTL is 0 for expired keys
						os.Setenv("ACTION", "EXPIRE") // Indicate this is an expiration event
						
						// Execute the expire script
						cmd := exec.Command(expireScript)
						output, err := cmd.CombinedOutput()
						if err != nil {
							log.Printf("Expire script failed for %s: %v\nOutput: %s", expiredKey, err, output)
						} else {
							if os.Getenv("DEBUG") != "" {
								log.Printf("Expire script succeeded for %s:\n%s", expiredKey, output)
							} else {
								log.Printf("Expire script executed successfully for %s", expiredKey)
							}
						}
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
		//dnsClient := &dns.Client{Net: "udp"}

		// Set EDNS Client Subnet so that upstream DNS servers receive the real client IP
		// This enables location-aware responses and proper geo-blocking by upstream servers
		if ednsAdd != "" {
			// Parse and validate the client IP address
			clientIP := net.ParseIP(from)
			if clientIP == nil {
				// ASSUMPTION: If client IP is invalid, log and skip EDNS to avoid breaking the request
				log.Printf("WARNING: Invalid client IP '%s' for EDNS, skipping EDNS processing", from)
			} else {
				// Check if request already has EDNS OPT records to avoid duplicates
				hasExistingOPT := false
				for _, rr := range r.Extra {
					if rr.Header().Rrtype == dns.TypeOPT {
						hasExistingOPT = true
						break
					}
				}
				
				if !hasExistingOPT {
					// Create properly formed OPT record with EDNS Client Subnet
					o := new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.SetUDPSize(4096) // Set appropriate buffer size for EDNS
					
					// Create EDNS Client Subnet option
					e := new(dns.EDNS0_SUBNET)
					e.Code = dns.EDNS0SUBNET
					e.SourceScope = 0 // Always 0 for queries
					
					// ASSUMPTION: Determine IPv4 vs IPv6 and set appropriate family/netmask
					// IPv4 addresses get family=1, netmask=32
					// IPv6 addresses get family=2, netmask=128
					if clientIP.To4() != nil {
						// IPv4 address
						e.Family = 1
						e.SourceNetmask = 32
						e.Address = clientIP.To4()
					} else {
						// IPv6 address  
						e.Family = 2
						e.SourceNetmask = 128
						e.Address = clientIP.To16()
					}
					
					o.Option = append(o.Option, e)
					r.Extra = append(r.Extra, o)
					
					if os.Getenv("DEBUG") != "" {
						log.Printf("Added EDNS Client Subnet for %s (family=%d, netmask=%d)", from, e.Family, e.SourceNetmask)
					}
				} else {
					// QUESTION: Should we modify existing OPT record or leave it alone?
					// ASSUMPTION: Leave existing OPT records untouched to avoid conflicts
					if os.Getenv("DEBUG") != "" {
						log.Printf("Request already has EDNS OPT record, skipping EDNS Client Subnet addition")
					}
				}
			}
		}
		dnsClient := &dns.Client{Net: "udp"}
		a, _, err := dnsClient.Exchange(r, upstream)
		if err != nil {
			log.Printf("DNS query failed: %v", err)
			dns.HandleFailed(w, r)
			return
		}
		if a == nil {
			log.Printf("Empty DNS response from upstream")
			dns.HandleFailed(w, r)
			return
		}
		if os.Getenv("DEBUG") != "" {
			log.Printf("Response from upstream %s:\n%s\n", upstream, a)
		}

		var numAnswers = len(a.Answer)

		var ipAddress, _ = netip.ParseAddr("127.0.0.1")
		var loStart, _ = netip.ParseAddr("127.0.0.0")
		var loEnd, _ = netip.ParseAddr("127.255.255.255")
		var openRange, _ = netip.ParseAddr("0.0.0.0")
		// IPv6 localhost and open range addresses
		var loV6, _ = netip.ParseAddr("::1")        // IPv6 localhost
		var openRangeV6, _ = netip.ParseAddr("::")   // IPv6 unspecified address
		var padTtl uint32 = 0

		var foundAddressRecords bool = false // true if A or AAAA records found
		var ipAddresses []netip.Addr // collect all IP addresses when HANDLE_ALL_IPS is set
		var firstIPIndex int = -1
		
		for i := range numAnswers {
			var currentIP netip.Addr
			var isAddressRecord bool = false
			
			// Handle A records (IPv4)
			if arec, ok := a.Answer[i].(*dns.A); ok {
				foundAddressRecords = true
				isAddressRecord = true
				currentIP, _ = netip.ParseAddr(arec.A.String())
			}
			// Handle AAAA records (IPv6)  
			if aaaarec, ok := a.Answer[i].(*dns.AAAA); ok {
				foundAddressRecords = true
				isAddressRecord = true
				currentIP, _ = netip.ParseAddr(aaaarec.AAAA.String())
			}
			
			if isAddressRecord {
				// padTtl is used in Redis TTL and in invoked scripts,
				// while ttl is used in client response
				ttl := a.Answer[i].Header().Ttl
				padTtl = ttl
				// Validate TTL
				if !validateTTL(ttl) {
					log.Printf("Invalid TTL: %d", ttl)
					continue
				}
				
				// pad very low TTLs
				if ttl < 30 {
					padTtl = ttl + 30
				}
				// clamp TTL at 1 hour
				if ttl > 3600 {
					padTtl = 3600
					a.Answer[i].Header().Ttl = 3600 // to the client as well
				}
				
				if handleAllIPs != "" {
					// collect all IP addresses for processing
					ipAddresses = append(ipAddresses, currentIP)
					if firstIPIndex == -1 {
						firstIPIndex = i
					}
				} else {
					// original behavior: handle only first address record
					ipAddress = currentIP
					A := a.Answer[0 : i+1]
					a.Answer = A
					break
				}
			}
		}
		
		// when HANDLE_ALL_IPS is set, set ipAddress to first IP for client response
		// but we'll process all IPs in the firewall logic below
		if handleAllIPs != "" && len(ipAddresses) > 0 {
			ipAddress = ipAddresses[0]
			// respond with all records up to the last A record
			if firstIPIndex != -1 {
				A := a.Answer[0 : firstIPIndex+len(ipAddresses)]
				a.Answer = A
			}
		}

		// helper function to process individual IP addresses
		processIP := func(targetIP netip.Addr) {
			// Check if IP is in localhost range (IPv4 or IPv6) or is open range
			isLocalhost := false
			if targetIP.Is4() {
				isLocalhost = inRange(loStart, loEnd, targetIP) || targetIP == openRange
			} else if targetIP.Is6() {
				isLocalhost = targetIP == loV6 || targetIP == openRangeV6
			}
			
			if !isLocalhost {
				newTtl := time.Duration(padTtl) * time.Second
				newTtlS := strconv.FormatFloat(newTtl.Seconds(), 'f', -1, 64)
				domain := r.Question[0].Name
				
				// Validate domain name
				if !validateDomain(domain) {
					log.Printf("Invalid domain: %s", domain)
					return // continue processing other IPs instead of failing entire request
				}
				
				key := "rules:" + from + ":" + targetIP.String() + ":" + domain
				
				// Sanitize environment variables to prevent injection  
				sanitizedClientIP := sanitizeForShell(from)
				sanitizedResolvedIP := sanitizeForShell(targetIP.String())
				sanitizedDomain := sanitizeForShell(domain)
				sanitizedTTL := sanitizeForShell(newTtlS)
				
				os.Setenv("CLIENT_IP", sanitizedClientIP)
				os.Setenv("RESOLVED_IP", sanitizedResolvedIP)
				os.Setenv("DOMAIN", sanitizedDomain)
				os.Setenv("TTL", sanitizedTTL)
				_, err := redisClient.Get(ctx, key).Result()
				// insert into Redis
				if err != nil {
					log.Printf("Add %s for %s, %s %s", targetIP, from, domain, newTtl)
					resp, err := redisClient.Set(ctx, key, newTtl, newTtl).Result()
					if err != nil {
						log.Printf("Unable to add key to Redis! %s", err.Error())
					}
					if os.Getenv("DEBUG") != "" {
						log.Printf("Redis insert: %s", resp)
					}
					// first appearance, invoke custom script
					if invoke != "" {
						cmd := exec.Command(invoke)
						output, err := cmd.CombinedOutput()
						if err != nil {
							log.Printf("Invoke command failed: %v\nOutput: %s", err, output)
							// Continue processing instead of fatal exit
						} else if os.Getenv("DEBUG") != "" {
							fmt.Printf("Invoke command succeeded:\n%s", output)
						}
					}
				} else {
					log.Printf("Update %s for %s, %s %s", targetIP, from, domain, newTtl)
					resp, err := redisClient.Set(ctx, key, "", newTtl).Result()
					if err != nil {
						log.Printf("Unable to add key to Redis! %s", err.Error())
					}
					if os.Getenv("DEBUG") != "" {
						log.Printf("Redis insert: %s", resp)
					}
					if invoke != "" && invoke_always != "" {
						cmd := exec.Command(invoke)
						output, err := cmd.CombinedOutput()
						if err != nil {
							log.Printf("Invoke command failed: %v\nOutput: %s", err, output)
							// Continue processing instead of fatal exit
						} else if os.Getenv("DEBUG") != "" {
							fmt.Printf("Invoke command succeeded:\n%s", output)
						}
					}
				}
			}
		}

		// only target A and AAAA records  
		if foundAddressRecords {
			if handleAllIPs != "" && len(ipAddresses) > 0 {
				// process all collected IP addresses
				for _, ip := range ipAddresses {
					processIP(ip)
				}
			} else {
				// original behavior: process only the first IP
				processIP(ipAddress)
			}
		}
		w.WriteMsg(a)

		// dropping request
	})
	return nil
}

// startWebUI starts the web UI server for rule management
func startWebUI(port string, redisClient *redis.Client) {
	// ASSUMPTION: Web UI should be simple and lightweight, using built-in HTML templates
	log.Printf("Starting web UI server on port %s", port)
	
	// Serve static content (CSS, JS) if needed
	http.HandleFunc("/", handleUIHome)
	http.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		handleAPIRules(w, r, redisClient)
	})
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		handleAPIStats(w, r, redisClient)
	})
	http.HandleFunc("/api/rules/delete", func(w http.ResponseWriter, r *http.Request) {
		handleAPIDeleteRule(w, r, redisClient)
	})
	
	// QUESTION: Should we enable HTTPS? For now, using HTTP for simplicity
	// ASSUMPTION: This is intended for internal/localhost use, so HTTP is acceptable
	server := &http.Server{
		Addr:    ":" + port,
		Handler: nil, // Use default ServeMux
		// ASSUMPTION: Set reasonable timeouts to prevent resource exhaustion
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Web UI server failed: %v", err)
	}
}

// handleUIHome serves the main HTML page
func handleUIHome(w http.ResponseWriter, r *http.Request) {
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
        
        <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
        
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
                const stats = await statsResponse.json();
                
                document.getElementById('totalRules').textContent = stats.total_rules;
                document.getElementById('activeClients').textContent = stats.active_clients;
                document.getElementById('uniqueDomains').textContent = stats.unique_domains;
                document.getElementById('uniqueIPs').textContent = stats.unique_ips;
                
                // Load rules
                const rulesResponse = await fetch('/api/rules');
                const rules = await rulesResponse.json();
                
                const tbody = document.getElementById('rulesBody');
                tbody.innerHTML = '';
                
                rules.forEach(rule => {
                    const row = document.createElement('tr');
                    row.innerHTML = ` + "`" + `
                        <td>${rule.client_ip}</td>
                        <td>${rule.resolved_ip}</td>
                        <td class="domain">${rule.domain}</td>
                        <td class="ttl">${rule.ttl}</td>
                        <td>${new Date(rule.expires_at).toLocaleString()}</td>
                        <td>
                            <button class="delete-btn" onclick="deleteRule('${rule.key}')">Delete</button>
                        </td>
                    ` + "`" + `;
                    tbody.appendChild(row);
                });
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('rulesTable').style.display = 'table';
                
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Error loading data: ' + error.message;
            }
        }
        
        async function deleteRule(key) {
            if (!confirm('Are you sure you want to delete this rule?')) {
                return;
            }
            
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
        
        // Load data on page load
        window.onload = loadData;
        
        // Auto-refresh every 30 seconds
        setInterval(loadData, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlTemplate))
}

// handleAPIRules returns all firewall rules as JSON
func handleAPIRules(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	ctx := context.Background()
	
	// ASSUMPTION: Get all keys matching our pattern "rules:*"
	keys, err := redisClient.Keys(ctx, "rules:*").Result()
	if err != nil {
		http.Error(w, "Error fetching rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	var rules []FirewallRule
	
	for _, key := range keys {
		// Parse key format: "rules:client:ip:domain"
		parts := strings.Split(key, ":")
		if len(parts) < 4 {
			continue // Skip malformed keys
		}
		
		clientIP := parts[1]
		resolvedIP := parts[2]
		domain := strings.Join(parts[3:], ":") // Domain might contain colons
		
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

// handleAPIStats returns statistics about the firewall rules
func handleAPIStats(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
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
		parts := strings.Split(key, ":")
		if len(parts) < 4 {
			continue
		}
		
		clientIP := parts[1]
		resolvedIP := parts[2]
		domain := strings.Join(parts[3:], ":")
		
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
	result, err := redisClient.Del(ctx, req.Key).Result()
	if err != nil {
		http.Error(w, "Error deleting rule: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	if result == 0 {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	
	log.Printf("Manually deleted rule: %s", req.Key)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
