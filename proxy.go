package main

import (
	"context"
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

func inRange(ipLow, ipHigh, ip netip.Addr) bool {
	return ipLow.Compare(ip) <= 0 && ipHigh.Compare(ip) > 0
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
			
			// Extract network from key (TTL_PAD_SECONDS_192_168_1_0_24 -> 192.168.1.0/24)
			networkPart := strings.TrimPrefix(key, "TTL_PAD_SECONDS_")
			cidr := strings.ReplaceAll(networkPart, "_", ".")
			// Replace the last dot with a slash for CIDR notation
			lastDot := strings.LastIndex(cidr, ".")
			if lastDot > 0 {
				cidr = cidr[:lastDot] + "/" + cidr[lastDot+1:]
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
		a, _, _ := dnsClient.Exchange(r, upstream)
		//if err != nil {
		//	return err
		//}
		if os.Getenv("DEBUG") != "" {
			log.Printf("Response from upstream %s:\n%s\n", upstream, a)
		}

		var numAnswers = len(a.Answer)

		var ipAddress, _ = netip.ParseAddr("127.0.0.1")
		var loStart, _ = netip.ParseAddr("127.0.0.0")
		var loEnd, _ = netip.ParseAddr("127.255.255.255")
		var openRange, _ = netip.ParseAddr("0.0.0.0")
		var padTtl uint32 = 0

		var recordA bool = false
		for i := range numAnswers {
			if arec, ok := a.Answer[i].(*dns.A); ok {
				recordA = true
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
				// TODO: add option to handle all IPs
				ipAddress, _ = netip.ParseAddr(arec.A.String())
				A := a.Answer[0 : i+1]
				a.Answer = A
				break
			}
		}

		// only target A records
		if recordA {
			if !(inRange(loStart, loEnd, ipAddress) || ipAddress == openRange) {
				newTtl := time.Duration(padTtl) * time.Second
				newTtlS := strconv.FormatFloat(newTtl.Seconds(), 'f', -1, 64)
				domain := r.Question[0].Name
				key := "rules|" + from + "|" + ipAddress.String() + "|" + domain

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
						// first appearance, invoke custom script
						if invoke != "" {
							cmd := exec.Command("/bin/sh", invoke)
							cmd.Env = append(os.Environ(),
								"CLIENT_IP="+from,
								"RESOLVED_IP="+ipAddress.String(),
								"DOMAIN="+domain,
								"TTL="+newTtlS)
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
						if invoke != "" && invoke_always != "" {
							cmd := exec.Command("/bin/sh", invoke)
							cmd.Env = append(os.Environ(),
								"CLIENT_IP="+from,
								"RESOLVED_IP="+ipAddress.String(),
								"DOMAIN="+domain,
								"TTL="+newTtlS)
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
