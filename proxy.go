package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

		// Set EDNS so that Pi-hole (or whatever upstream) receives the real client IP
		// If you already have EDNS records added, you can set environmental variable
		// DISABLE_EDNS to any value to disable this.
		// Don't enable!!, this currently breaks many requests
		if ednsAdd != "" {
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			e.Family = 1         // 1 for IPv4 source address, 2 for IPv6
			e.SourceNetmask = 32 // 32 for IPV4, 128 for IPv6
			e.SourceScope = 0
			e.Address = net.ParseIP(from).To4() // for IPv4
			// e.Address = net.ParseIP("2001:7b8:32a::2") // for IPV6
			o.Option = append(o.Option, e)
			if os.Getenv("DEBUG") != "" {
				log.Printf("EDNS in Request %s:\n", r.Extra)
			}
			r.Extra = append(r.Extra, o)
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
