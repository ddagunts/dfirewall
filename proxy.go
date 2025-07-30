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
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type Route struct {
	Zone string
	From net.IP
	To   net.IP
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

	//addAllIPs := os.Getenv("ADD_ALL_IPS")

	redisEnv := os.Getenv("REDIS")
	if redisEnv == "" {
		log.Printf("Missing REDIS env var, this isn't meant to be run without Redis")
	}

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
				padTtl = ttl
				// pad very low TTLs
				if ttl < 30 {
					padTtl = ttl + 30
				}
				// clamp TTL at 1 hour
				if ttl > 3600 {
					padTtl = 3600
					a.Answer[i].Header().Ttl = 3600 // to the client as well
				}

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
				key := "rules:" + from + ":" + ipAddress.String() + ":" + domain
				os.Setenv("CLIENT_IP", from)
				os.Setenv("RESOLVED_IP", ipAddress.String())
				os.Setenv("DOMAIN", domain)
				os.Setenv("TTL", newTtlS)
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
						cmd := exec.Command(invoke)
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
						cmd := exec.Command(invoke)
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
		w.WriteMsg(a)

		// dropping request
	})
	return nil
}
