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

type ClientTTLConfig struct {
	networks map[*net.IPNet]int
	defaults int
}

type ClientBlacklistConfig struct {
	networks map[*net.IPNet][]string
	defaults []string
}

type ClientWhitelistConfig struct {
	networks map[*net.IPNet][]string
	defaults []string
	enabled  bool
}

type HistoricalRule struct {
	ClientIP    string `json:"client_ip"`
	ResolvedIP  string `json:"resolved_ip"`
	Domain      string `json:"domain"`
	RecordType  string `json:"record_type"`
	Action      string `json:"action"`
	Timestamp   int64  `json:"timestamp"`
	TTL         string `json:"ttl,omitempty"`
}

func inRange(ipLow, ipHigh, ip netip.Addr) bool {
	return ipLow.Compare(ip) <= 0 && ipHigh.Compare(ip) > 0
}

func hasEDNSSubnet(r *dns.Msg) bool {
	for _, rr := range r.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if _, ok := option.(*dns.EDNS0_SUBNET); ok {
					return true
				}
			}
		}
	}
	return false
}

func parseClientBlacklistConfig() *ClientBlacklistConfig {
	config := &ClientBlacklistConfig{
		networks: make(map[*net.IPNet][]string),
		defaults: []string{},
	}

	// Check for default blacklist domains
	if blacklistEnv := os.Getenv("DOMAIN_BLACKLIST_DEFAULT"); blacklistEnv != "" {
		domains := strings.Split(blacklistEnv, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		config.defaults = domains
		log.Printf("DOMAIN_BLACKLIST_DEFAULT is set to: %v", domains)
	} else {
		log.Printf("DOMAIN_BLACKLIST_DEFAULT is not set, no default blacklist")
	}

	// Parse all environment variables that match the pattern DOMAIN_BLACKLIST_*
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "DOMAIN_BLACKLIST_") && !strings.HasSuffix(env, "_DEFAULT") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			
			key := parts[0]
			value := parts[1]
			
			// Extract network from key 
			// IPv4: DOMAIN_BLACKLIST_192_168_1_0_24 -> 192.168.1.0/24
			// IPv6: DOMAIN_BLACKLIST_2001_db8_1__64 -> 2001:db8:1::/64
			networkPart := strings.TrimPrefix(key, "DOMAIN_BLACKLIST_")
			var cidr string
			
			if strings.Contains(networkPart, "__") {
				// IPv6 format: 2001_db8_1__64 -> 2001:db8:1::/64
				parts := strings.Split(networkPart, "__")
				if len(parts) == 2 {
					ipv6Part := strings.ReplaceAll(parts[0], "_", ":")
					cidr = ipv6Part + "::" + "/" + parts[1]
				}
			} else {
				// IPv4 format: 192_168_1_0_24 -> 192.168.1.0/24
				cidr = strings.ReplaceAll(networkPart, "_", ".")
				lastDot := strings.LastIndex(cidr, ".")
				if lastDot > 0 {
					cidr = cidr[:lastDot] + "/" + cidr[lastDot+1:]
				}
			}
			
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				domains := strings.Split(value, ",")
				for i := range domains {
					domains[i] = strings.TrimSpace(domains[i])
				}
				config.networks[network] = domains
				log.Printf("Domain blacklist for %s: %v", cidr, domains)
			} else {
				log.Printf("Invalid network format for %s: %s", key, cidr)
			}
		}
	}
	
	return config
}

func (config *ClientBlacklistConfig) getBlacklistedDomains(clientIP string) []string {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return config.defaults
	}
	
	// Check if client IP matches any configured networks
	for network, domains := range config.networks {
		if network.Contains(ip) {
			return domains
		}
	}
	
	// Return default if no network matches
	return config.defaults
}

func (config *ClientBlacklistConfig) isDomainBlacklisted(clientIP string, domain string) bool {
	blacklistedDomains := config.getBlacklistedDomains(clientIP)
	domain = strings.TrimSuffix(domain, ".")
	
	for _, blacklistedDomain := range blacklistedDomains {
		blacklistedDomain = strings.TrimSuffix(blacklistedDomain, ".")
		// Exact match
		if strings.EqualFold(domain, blacklistedDomain) {
			return true
		}
		// Subdomain match (e.g., blacklisting "example.com" blocks "sub.example.com")
		if strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(blacklistedDomain)) {
			return true
		}
	}
	
	return false
}

func parseClientWhitelistConfig() *ClientWhitelistConfig {
	config := &ClientWhitelistConfig{
		networks: make(map[*net.IPNet][]string),
		defaults: []string{},
		enabled:  false,
	}

	// Check if whitelist mode is enabled
	if whitelistMode := os.Getenv("DOMAIN_WHITELIST_MODE"); whitelistMode != "" {
		config.enabled = true
		log.Printf("DOMAIN_WHITELIST_MODE is enabled - all domains blocked by default except whitelisted")
	}

	// Only parse whitelist configurations if whitelist mode is enabled
	if !config.enabled {
		return config
	}

	// Check for default whitelist domains
	if whitelistEnv := os.Getenv("DOMAIN_WHITELIST_DEFAULT"); whitelistEnv != "" {
		domains := strings.Split(whitelistEnv, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		config.defaults = domains
		log.Printf("DOMAIN_WHITELIST_DEFAULT is set to: %v", domains)
	} else {
		log.Printf("DOMAIN_WHITELIST_DEFAULT is not set, no default whitelist")
	}

	// Parse all environment variables that match the pattern DOMAIN_WHITELIST_*
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "DOMAIN_WHITELIST_") && !strings.HasSuffix(env, "_DEFAULT") && !strings.HasSuffix(env, "_MODE") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			
			key := parts[0]
			value := parts[1]
			
			// Extract network from key 
			// IPv4: DOMAIN_WHITELIST_192_168_1_0_24 -> 192.168.1.0/24
			// IPv6: DOMAIN_WHITELIST_2001_db8_1__64 -> 2001:db8:1::/64
			networkPart := strings.TrimPrefix(key, "DOMAIN_WHITELIST_")
			var cidr string
			
			if strings.Contains(networkPart, "__") {
				// IPv6 format: 2001_db8_1__64 -> 2001:db8:1::/64
				parts := strings.Split(networkPart, "__")
				if len(parts) == 2 {
					ipv6Part := strings.ReplaceAll(parts[0], "_", ":")
					cidr = ipv6Part + "::" + "/" + parts[1]
				}
			} else {
				// IPv4 format: 192_168_1_0_24 -> 192.168.1.0/24
				cidr = strings.ReplaceAll(networkPart, "_", ".")
				lastDot := strings.LastIndex(cidr, ".")
				if lastDot > 0 {
					cidr = cidr[:lastDot] + "/" + cidr[lastDot+1:]
				}
			}
			
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				domains := strings.Split(value, ",")
				for i := range domains {
					domains[i] = strings.TrimSpace(domains[i])
				}
				config.networks[network] = domains
				log.Printf("Domain whitelist for %s: %v", cidr, domains)
			} else {
				log.Printf("Invalid network format for %s: %s", key, cidr)
			}
		}
	}
	
	return config
}

func (config *ClientWhitelistConfig) getWhitelistedDomains(clientIP string) []string {
	if !config.enabled {
		return []string{}
	}
	
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return config.defaults
	}
	
	// Check if client IP matches any configured networks
	for network, domains := range config.networks {
		if network.Contains(ip) {
			return domains
		}
	}
	
	// Return default if no network matches
	return config.defaults
}

func (config *ClientWhitelistConfig) isDomainWhitelisted(clientIP string, domain string) bool {
	if !config.enabled {
		return true // If whitelist mode is disabled, allow all domains
	}
	
	whitelistedDomains := config.getWhitelistedDomains(clientIP)
	domain = strings.TrimSuffix(domain, ".")
	
	for _, whitelistedDomain := range whitelistedDomains {
		whitelistedDomain = strings.TrimSuffix(whitelistedDomain, ".")
		// Exact match
		if strings.EqualFold(domain, whitelistedDomain) {
			return true
		}
		// Subdomain match (e.g., whitelisting "example.com" allows "sub.example.com")
		if strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(whitelistedDomain)) {
			return true
		}
	}
	
	return false
}

func parseClientTTLConfig() *ClientTTLConfig {
	config := &ClientTTLConfig{
		networks: make(map[*net.IPNet]int),
		defaults: 30, // default 30 seconds
	}

	// Check for default TTL padding
	if ttlPadEnv := os.Getenv("TTL_PAD_SECONDS_DEFAULT"); ttlPadEnv != "" {
		if value, err := strconv.Atoi(ttlPadEnv); err == nil && value >= 0 {
			config.defaults = value
			log.Printf("TTL_PAD_SECONDS_DEFAULT is set to %d seconds", value)
		} else {
			log.Printf("Invalid TTL_PAD_SECONDS_DEFAULT value: %s, using default 30 seconds", ttlPadEnv)
		}
	} else {
		log.Printf("TTL_PAD_SECONDS_DEFAULT is not set, using default 30 seconds")
	}

	// Parse all environment variables that match the pattern TTL_PAD_SECONDS_*
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "TTL_PAD_SECONDS_") && !strings.HasSuffix(env, "_DEFAULT") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			
			key := parts[0]
			value := parts[1]
			
			// Extract network from key 
			// IPv4: TTL_PAD_SECONDS_192_168_1_0_24 -> 192.168.1.0/24
			// IPv6: TTL_PAD_SECONDS_2001_db8_1__64 -> 2001:db8:1::/64
			networkPart := strings.TrimPrefix(key, "TTL_PAD_SECONDS_")
			var cidr string
			
			if strings.Contains(networkPart, "__") {
				// IPv6 format: 2001_db8_1__64 -> 2001:db8:1::/64
				parts := strings.Split(networkPart, "__")
				if len(parts) == 2 {
					ipv6Part := strings.ReplaceAll(parts[0], "_", ":")
					cidr = ipv6Part + "::" + "/" + parts[1]
				}
			} else {
				// IPv4 format: 192_168_1_0_24 -> 192.168.1.0/24
				cidr = strings.ReplaceAll(networkPart, "_", ".")
				lastDot := strings.LastIndex(cidr, ".")
				if lastDot > 0 {
					cidr = cidr[:lastDot] + "/" + cidr[lastDot+1:]
				}
			}
			
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				if ttlValue, err := strconv.Atoi(value); err == nil && ttlValue >= 0 {
					config.networks[network] = ttlValue
					log.Printf("TTL padding for %s: %d seconds", cidr, ttlValue)
				} else {
					log.Printf("Invalid TTL value for %s: %s", cidr, value)
				}
			} else {
				log.Printf("Invalid network format for %s: %s", key, cidr)
			}
		}
	}
	
	return config
}

func (config *ClientTTLConfig) getTTLPadding(clientIP string) int {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return config.defaults
	}
	
	// Check if client IP matches any configured networks
	for network, ttlPad := range config.networks {
		if network.Contains(ip) {
			return ttlPad
		}
	}
	
	// Return default if no network matches
	return config.defaults
}

func isClientDomainBlocked(ctx context.Context, redisClient *redis.Client, clientIP, domain string) bool {
	key := "blocked_domains|" + clientIP
	blockedDomains, err := redisClient.SMembers(ctx, key).Result()
	if err != nil {
		return false
	}
	
	domain = strings.TrimSuffix(domain, ".")
	
	for _, blockedDomain := range blockedDomains {
		blockedDomain = strings.TrimSuffix(blockedDomain, ".")
		// Exact match
		if strings.EqualFold(domain, blockedDomain) {
			return true
		}
		// Subdomain match (e.g., blocking "example.com" blocks "sub.example.com")
		if strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(blockedDomain)) {
			return true
		}
	}
	
	return false
}

func recordHistoricalRule(ctx context.Context, redisClient *redis.Client, clientIP, resolvedIP, domain, recordType, action, ttl string) error {
	if redisClient == nil {
		return nil
	}

	historicalRule := HistoricalRule{
		ClientIP:   clientIP,
		ResolvedIP: resolvedIP,
		Domain:     domain,
		RecordType: recordType,
		Action:     action,
		Timestamp:  time.Now().Unix(),
		TTL:        ttl,
	}

	data, err := json.Marshal(historicalRule)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("history|%s|%d", clientIP, historicalRule.Timestamp)
	return redisClient.Set(ctx, key, string(data), 30*24*time.Hour).Err()
}

func Register(rt Route) error {
	return RegisterWithRedis(rt, nil)
}

func RegisterWithRedis(rt Route, redisClient *redis.Client) error {
	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		log.Fatal("Missing UPSTREAM env var: please declare with UPSTREAM=host:port")
	}
	ednsAdd := os.Getenv("ENABLE_EDNS")

	//addAllIPs := os.Getenv("ADD_ALL_IPS")

	invoke := os.Getenv("INVOKE_SCRIPT")
	if invoke == "" {
		log.Printf("INVOKE_SCRIPT env var not set, not executing script for new IPs")
	} else {
		log.Printf("INVOKE_SCRIPT is set to %s", invoke)
	}

	invoke_always := os.Getenv("INVOKE_ALWAYS")
	if invoke_always == "" {
		log.Printf("INVOKE_ALWAYS is not set, only executing INVOKE script for IPs not present in Redis")
	} else {
		log.Printf("INVOKE_ALWAYS is set, executing INVOKE script for every matching request")
	}

	// Parse per-client TTL configuration
	ttlConfig := parseClientTTLConfig()

	// Parse per-client domain blacklist configuration  
	blacklistConfig := parseClientBlacklistConfig()

	// Parse per-client domain whitelist configuration
	whitelistConfig := parseClientWhitelistConfig()

	ctx := context.Background()

	if redisClient == nil {
		redisEnv := os.Getenv("REDIS")
		if redisEnv == "" {
			log.Printf("Missing REDIS env var, this isn't meant to be run without Redis")
		} else {
			opt, err := redis.ParseURL(redisEnv)
			if err != nil {
				panic(err)
			}
			redisClient = redis.NewClient(opt)

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
		}
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

		if os.Getenv("DEBUG") != "" {
			log.Printf("Request from client %s:\n%s\n", from, r)
		}

		// Check domain filtering (blacklist and whitelist) for this client
		if len(r.Question) > 0 {
			domain := r.Question[0].Name
			
			// Check Redis-based blocked domains first
			if redisClient != nil && isClientDomainBlocked(ctx, redisClient, from, domain) {
				log.Printf("Blocked Redis-blocked domain %s for client %s", domain, from)
				// Return NXDOMAIN response
				a := new(dns.Msg)
				a.SetReply(r)
				a.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(a)
				return
			}
			
			// Check environment-based blacklist
			if blacklistConfig.isDomainBlacklisted(from, domain) {
				log.Printf("Blocked blacklisted domain %s for client %s", domain, from)
				// Return NXDOMAIN response
				a := new(dns.Msg)
				a.SetReply(r)
				a.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(a)
				return
			}
			
			// Check whitelist (only if whitelist mode is enabled)
			if !whitelistConfig.isDomainWhitelisted(from, domain) {
				log.Printf("Blocked non-whitelisted domain %s for client %s", domain, from)
				// Return NXDOMAIN response
				a := new(dns.Msg)
				a.SetReply(r)
				a.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(a)
				return
			}
		}
		//dnsClient := &dns.Client{Net: "udp"}

		// Set EDNS so that Pi-hole (or whatever upstream) receives the real client IP
		// If you already have EDNS records added, you can set environmental variable
		// DISABLE_EDNS to any value to disable this.
		// Only add EDNS subnet if one doesn't already exist in the request
		if ednsAdd != "" && !hasEDNSSubnet(r) {
			clientIP := net.ParseIP(from)
			if clientIP != nil {
				o := new(dns.OPT)
				o.Hdr.Name = "."
				o.Hdr.Rrtype = dns.TypeOPT
				o.Hdr.Class = dns.DefaultMsgSize // Set UDP payload size
				o.Hdr.Ttl = 0 // Set extended RCODE and flags to 0
				
				e := new(dns.EDNS0_SUBNET)
				e.Code = dns.EDNS0SUBNET
				
				if clientIP.To4() != nil {
					// IPv4 address - use /24 netmask for better compatibility
					e.Family = 1
					e.SourceNetmask = 24
					e.SourceScope = 0
					// Apply mask to the client IP
					maskedIP := clientIP.To4().Mask(net.CIDRMask(24, 32))
					e.Address = maskedIP
				} else if clientIP.To16() != nil {
					// IPv6 address - use /64 netmask for better compatibility
					e.Family = 2
					e.SourceNetmask = 64
					e.SourceScope = 0
					// Apply mask to the client IP
					maskedIP := clientIP.To16().Mask(net.CIDRMask(64, 128))
					e.Address = maskedIP
				} else {
					// Skip EDNS if IP parsing fails
					if os.Getenv("DEBUG") != "" {
						log.Printf("Invalid client IP for EDNS: %s", from)
					}
					goto skipEDNS
				}
				
				o.Option = append(o.Option, e)
				if os.Getenv("DEBUG") != "" {
					log.Printf("Adding EDNS subnet for client %s (masked: %s)", from, e.Address.String())
				}
				r.Extra = append(r.Extra, o)
			} else {
				if os.Getenv("DEBUG") != "" {
					log.Printf("Could not parse client IP for EDNS: %s", from)
				}
			}
			skipEDNS:
		} else if ednsAdd != "" && hasEDNSSubnet(r) {
			if os.Getenv("DEBUG") != "" {
				log.Printf("Request already contains EDNS subnet, not adding client IP %s", from)
			}
		}
		dnsClient := &dns.Client{Net: "udp"}
		a, _, err := dnsClient.Exchange(r, upstream)
		
		// If we get a truncated response, retry with TCP
		if a != nil && a.Truncated {
			if os.Getenv("DEBUG") != "" {
				log.Printf("Received truncated response from upstream, retrying with TCP")
			}
			tcpClient := &dns.Client{Net: "tcp"}
			a, _, err = tcpClient.Exchange(r, upstream)
		}
		if err != nil {
			log.Printf("DNS exchange error: %v", err)
			return
		}
		if os.Getenv("DEBUG") != "" {
			log.Printf("Response from upstream %s:\n%s\n", upstream, a)
		}

		var numAnswers = len(a.Answer)

		var ipAddress, _ = netip.ParseAddr("127.0.0.1")
		var loStartV4, _ = netip.ParseAddr("127.0.0.0")
		var loEndV4, _ = netip.ParseAddr("127.255.255.255")
		var loV6, _ = netip.ParseAddr("::1")
		var openRangeV4, _ = netip.ParseAddr("0.0.0.0")
		var openRangeV6, _ = netip.ParseAddr("::")
		var padTtl uint32 = 0
		var recordType string = ""

		var recordFound bool = false
		for i := range numAnswers {
			if arec, ok := a.Answer[i].(*dns.A); ok {
				recordFound = true
				recordType = "A"
				// padTtl is used in Redis TTL and in invoked scripts,
				// while ttl is used in client response
				ttl := a.Answer[i].Header().Ttl
				// clamp TTL at 1 hour for client response
				if ttl > 3600 {
					ttl = 3600
					a.Answer[i].Header().Ttl = 3600 // to the client as well
				}
				// pad TTL with per-client configured value (after clamping)
				clientTTLPad := ttlConfig.getTTLPadding(from)
				padTtl = ttl + uint32(clientTTLPad)

				// respond with all records prior to first A record, and first A record
				ipAddress, _ = netip.ParseAddr(arec.A.String())
				A := a.Answer[0 : i+1]
				a.Answer = A
				break
			} else if aaaarec, ok := a.Answer[i].(*dns.AAAA); ok {
				recordFound = true
				recordType = "AAAA"
				// padTtl is used in Redis TTL and in invoked scripts,
				// while ttl is used in client response
				ttl := a.Answer[i].Header().Ttl
				// clamp TTL at 1 hour for client response
				if ttl > 3600 {
					ttl = 3600
					a.Answer[i].Header().Ttl = 3600 // to the client as well
				}
				// pad TTL with per-client configured value (after clamping)
				clientTTLPad := ttlConfig.getTTLPadding(from)
				padTtl = ttl + uint32(clientTTLPad)

				// respond with all records prior to first AAAA record, and first AAAA record
				ipAddress, _ = netip.ParseAddr(aaaarec.AAAA.String())
				A := a.Answer[0 : i+1]
				a.Answer = A
				break
			}
		}

		// target both A and AAAA records
		if recordFound {
			// Check if IP should be excluded (localhost ranges and null routes)
			var shouldExclude bool
			if ipAddress.Is4() {
				shouldExclude = inRange(loStartV4, loEndV4, ipAddress) || ipAddress == openRangeV4
			} else if ipAddress.Is6() {
				shouldExclude = ipAddress == loV6 || ipAddress == openRangeV6
			}
			
			if !shouldExclude {
				newTtl := time.Duration(padTtl) * time.Second
				newTtlS := strconv.FormatFloat(newTtl.Seconds(), 'f', -1, 64)
				domain := r.Question[0].Name
				key := "rules|" + from + "|" + ipAddress.String() + "|" + domain + "|" + recordType

				// Validate inputs before passing to script
				if net.ParseIP(from) == nil {
					log.Printf("Invalid CLIENT_IP: %s", from)
					w.WriteMsg(a)
					return
				}
				if !ipAddress.IsValid() {
					log.Printf("Invalid RESOLVED_IP: %s", ipAddress.String())
					w.WriteMsg(a)
					return
				}
				if newTtl <= 0 {
					log.Printf("Invalid TTL: %s", newTtlS)
					w.WriteMsg(a)
					return
				}
				// Robust domain validation
				if strings.Contains(domain, "\x00") || len(domain) == 0 || len(domain) > 253 {
					log.Printf("Invalid DOMAIN: %s", domain)
					w.WriteMsg(a)
					return
				}
				// Check for valid DNS name format
				domain = strings.TrimSuffix(domain, ".")
				for _, label := range strings.Split(domain, ".") {
					if len(label) == 0 || len(label) > 63 {
						log.Printf("Invalid DOMAIN label length: %s", domain)
						w.WriteMsg(a)
						return
					}
					for i, r := range label {
						if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
							log.Printf("Invalid DOMAIN character: %s", domain)
							w.WriteMsg(a)
							return
						}
						if r == '-' && (i == 0 || i == len(label)-1) {
							log.Printf("Invalid DOMAIN hyphen position: %s", domain)
							w.WriteMsg(a)
							return
						}
					}
				}
				if redisClient != nil {
					_, err := redisClient.Get(ctx, key).Result()
					// insert into Redis
					if err != nil {
						log.Printf("Add %s for %s, %s %s", ipAddress, from, domain, newTtl)
						resp, err := redisClient.Set(ctx, key, newTtl, newTtl).Result()
						if err != nil {
							log.Printf("Unable to add key to Redis! %s", err.Error())
						}
						if os.Getenv("DEBUG") != "" {
							log.Printf("Redis insert: %s", resp)
						}
						// Record historical rule creation
						recordHistoricalRule(ctx, redisClient, from, ipAddress.String(), domain, recordType, "created", newTtlS)
						// first appearance, invoke custom script
						if invoke != "" {
							cmd := exec.Command("/bin/sh", invoke)
							cmd.Env = append(os.Environ(),
								"CLIENT_IP="+from,
								"RESOLVED_IP="+ipAddress.String(),
								"DOMAIN="+domain,
								"TTL="+newTtlS,
								"RECORD_TYPE="+recordType)
							output, err := cmd.CombinedOutput()
							if err != nil {
								if os.Getenv("DEBUG") != "" {
									log.Fatalf("Invoke command failed: %v\nOutput: %s", err, output)
								}
							}
							if os.Getenv("DEBUG") != "" {
								fmt.Printf("Invoke command succeeded:\n%s", output)
							}
						}
					} else {
						log.Printf("Update %s for %s, %s %s", ipAddress, from, domain, newTtl)
						resp, err := redisClient.Set(ctx, key, "", newTtl).Result()
						if err != nil {
							log.Printf("Unable to add key to Redis! %s", err.Error())
						}
						if os.Getenv("DEBUG") != "" {
							log.Printf("Redis insert: %s", resp)
						}
						// Record historical rule update
						recordHistoricalRule(ctx, redisClient, from, ipAddress.String(), domain, recordType, "updated", newTtlS)
						if invoke != "" && invoke_always != "" {
							cmd := exec.Command("/bin/sh", invoke)
							cmd.Env = append(os.Environ(),
								"CLIENT_IP="+from,
								"RESOLVED_IP="+ipAddress.String(),
								"DOMAIN="+domain,
								"TTL="+newTtlS,
								"RECORD_TYPE="+recordType)
							output, err := cmd.CombinedOutput()
							if err != nil {
								if os.Getenv("DEBUG") != "" {
									log.Fatalf("Invoke command failed: %v\nOutput: %s", err, output)
								}
							}
							if os.Getenv("DEBUG") != "" {
								fmt.Printf("Invoke command succeeded:\n%s", output)
							}
						}
					}
				}
			}
		}
		w.WriteMsg(a)

		// dropping request
	})
	return nil
}
