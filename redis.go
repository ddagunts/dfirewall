package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Input validation functions
var (
	validIPRegex     = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$`)
)

// createRedisClient creates and configures a Redis client with enhanced security features
func createRedisClient(redisEnv string) (*redis.Client, error) {
	// Start with standard URL parsing
	opt, err := redis.ParseURL(redisEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %v", err)
	}
	
	// Enhanced authentication support
	// REDIS_PASSWORD environment variable overrides URL password
	if redisPassword := os.Getenv("REDIS_PASSWORD"); redisPassword != "" {
		opt.Password = redisPassword
		log.Printf("Redis authentication enabled (password from REDIS_PASSWORD env var)")
	} else if opt.Password != "" {
		log.Printf("Redis authentication enabled (password from URL)")
	}
	
	// Enhanced TLS support
	if redisTLS := os.Getenv("REDIS_TLS"); redisTLS == "true" || redisTLS == "1" || redisTLS == "enabled" {
		opt.TLSConfig = &tls.Config{
			ServerName: opt.Addr, // Default to connection address
		}
		
		// TLS Certificate configuration
		if certFile := os.Getenv("REDIS_TLS_CERT"); certFile != "" {
			keyFile := os.Getenv("REDIS_TLS_KEY")
			if keyFile == "" {
				return nil, fmt.Errorf("REDIS_TLS_KEY is required when REDIS_TLS_CERT is specified")
			}
			
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load Redis TLS certificate: %v", err)
			}
			
			opt.TLSConfig.Certificates = []tls.Certificate{cert}
			log.Printf("Redis TLS client certificate loaded: %s", certFile)
		}
		
		// CA Certificate configuration
		if caFile := os.Getenv("REDIS_TLS_CA"); caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read Redis TLS CA certificate: %v", err)
			}
			
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse Redis TLS CA certificate")
			}
			
			opt.TLSConfig.RootCAs = caCertPool
			log.Printf("Redis TLS CA certificate loaded: %s", caFile)
		}
		
		// TLS Server Name Override
		if serverName := os.Getenv("REDIS_TLS_SERVER_NAME"); serverName != "" {
			opt.TLSConfig.ServerName = serverName
			log.Printf("Redis TLS server name override: %s", serverName)
		}
		
		// Skip certificate verification if requested (NOT recommended for production)
		if skipVerify := os.Getenv("REDIS_TLS_SKIP_VERIFY"); skipVerify == "true" || skipVerify == "1" {
			opt.TLSConfig.InsecureSkipVerify = true
			log.Printf("WARNING: Redis TLS certificate verification disabled - NOT recommended for production")
		}
		
		log.Printf("Redis TLS enabled")
	}
	
	// Connection pool and timeout configuration
	if maxRetries := os.Getenv("REDIS_MAX_RETRIES"); maxRetries != "" {
		if retries, err := strconv.Atoi(maxRetries); err == nil {
			opt.MaxRetries = retries
		}
	}
	
	if dialTimeout := os.Getenv("REDIS_DIAL_TIMEOUT"); dialTimeout != "" {
		if timeout, err := time.ParseDuration(dialTimeout); err == nil {
			opt.DialTimeout = timeout
		}
	}
	
	if readTimeout := os.Getenv("REDIS_READ_TIMEOUT"); readTimeout != "" {
		if timeout, err := time.ParseDuration(readTimeout); err == nil {
			opt.ReadTimeout = timeout
		}
	}
	
	if writeTimeout := os.Getenv("REDIS_WRITE_TIMEOUT"); writeTimeout != "" {
		if timeout, err := time.ParseDuration(writeTimeout); err == nil {
			opt.WriteTimeout = timeout
		}
	}
	
	if poolSize := os.Getenv("REDIS_POOL_SIZE"); poolSize != "" {
		if size, err := strconv.Atoi(poolSize); err == nil {
			opt.PoolSize = size
		}
	}
	
	// Create Redis client
	client := redis.NewClient(opt)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}
	
	// Log successful connection with security details
	connDetails := fmt.Sprintf("Connected to Redis at %s", opt.Addr)
	if opt.Password != "" {
		connDetails += " (authenticated)"
	}
	if opt.TLSConfig != nil {
		connDetails += " (TLS enabled)"
	}
	log.Printf("%s", connDetails)
	
	return client, nil
}

// Validation functions

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

// validateClientPattern validates IP patterns for client configurations
func validateClientPattern(pattern string) error {
	// ASSUMPTION: Support three pattern types:
	// 1. Single IP: "192.168.1.1"
	// 2. CIDR notation: "192.168.1.0/24"
	// 3. Regex pattern: starts with "regex:"
	
	if strings.HasPrefix(pattern, "regex:") {
		// Validate regex pattern
		regexPattern := strings.TrimPrefix(pattern, "regex:")
		_, err := regexp.Compile(regexPattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %v", err)
		}
		return nil
	}
	
	// Check if it's a CIDR notation
	if strings.Contains(pattern, "/") {
		_, _, err := net.ParseCIDR(pattern)
		if err != nil {
			return fmt.Errorf("invalid CIDR notation: %v", err)
		}
		return nil
	}
	
	// Check if it's a single IP address
	if net.ParseIP(pattern) == nil {
		return fmt.Errorf("pattern must be a valid IP address, CIDR notation, or regex pattern starting with 'regex:'")
	}
	
	return nil
}