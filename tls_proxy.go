package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type TLSProxy struct {
	redisClient *redis.Client
	enabled     bool
	proxyIP     string
	proxyPorts  []int
	listeners   []net.Listener
	clientConfig *ClientSNIConfig
	mu          sync.RWMutex
	ctx         context.Context
}

type ClientSNIConfig struct {
	networks map[*net.IPNet]bool
	defaults bool
}

type SNIMapping struct {
	OriginalDomain string
	RealIP         string
	ClientIP       string
	CreatedAt      time.Time
}

func parseClientSNIConfig() *ClientSNIConfig {
	config := &ClientSNIConfig{
		networks: make(map[*net.IPNet]bool),
		defaults: false,
	}

	// Check for default SNI verification setting
	if enableSNI := os.Getenv("ENABLE_SNI_VERIFICATION_DEFAULT"); enableSNI != "" {
		config.defaults = true
		log.Printf("ENABLE_SNI_VERIFICATION_DEFAULT is set, SNI verification enabled by default")
	} else {
		log.Printf("ENABLE_SNI_VERIFICATION_DEFAULT is not set, SNI verification disabled by default")
	}

	// Parse all environment variables that match the pattern ENABLE_SNI_VERIFICATION_*
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ENABLE_SNI_VERIFICATION_") && !strings.HasSuffix(env, "_DEFAULT") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			
			key := parts[0]
			value := parts[1]
			
			// Extract network from key 
			// IPv4: ENABLE_SNI_VERIFICATION_192_168_1_0_24 -> 192.168.1.0/24
			// IPv6: ENABLE_SNI_VERIFICATION_2001_db8_1__64 -> 2001:db8:1::/64
			networkPart := strings.TrimPrefix(key, "ENABLE_SNI_VERIFICATION_")
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
				enabled := value != "" && value != "0" && strings.ToLower(value) != "false"
				config.networks[network] = enabled
				log.Printf("SNI verification for %s: %v", cidr, enabled)
			} else {
				log.Printf("Invalid network format for %s: %s", key, cidr)
			}
		}
	}
	
	return config
}

func (config *ClientSNIConfig) isSNIEnabledForClient(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return config.defaults
	}
	
	// Check if client IP matches any configured networks
	for network, enabled := range config.networks {
		if network.Contains(ip) {
			return enabled
		}
	}
	
	// Return default if no network matches
	return config.defaults
}

func NewTLSProxy(redisClient *redis.Client) *TLSProxy {
	proxy := &TLSProxy{
		redisClient:  redisClient,
		enabled:      false,
		proxyIP:      "1.2.3.4",
		proxyPorts:   []int{443},
		listeners:    []net.Listener{},
		clientConfig: parseClientSNIConfig(),
		ctx:          context.Background(),
	}

	// Check if any SNI verification is enabled (either default or per-client)
	globalEnable := os.Getenv("ENABLE_SNI_VERIFICATION")
	hasClientConfigs := len(proxy.clientConfig.networks) > 0 || proxy.clientConfig.defaults
	
	if globalEnable != "" || hasClientConfigs {
		proxy.enabled = true
		log.Printf("TLS SNI verification enabled (global or per-client)")

		if sniProxyIP := os.Getenv("SNI_PROXY_IP"); sniProxyIP != "" {
			proxy.proxyIP = sniProxyIP
			log.Printf("SNI proxy IP set to: %s", sniProxyIP)
		}

		if sniProxyPorts := os.Getenv("SNI_PROXY_PORTS"); sniProxyPorts != "" {
			var ports []int
			for _, portStr := range strings.Split(sniProxyPorts, ",") {
				portStr = strings.TrimSpace(portStr)
				if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
					ports = append(ports, port)
				} else {
					log.Printf("Invalid SNI proxy port: %s", portStr)
				}
			}
			if len(ports) > 0 {
				proxy.proxyPorts = ports
				log.Printf("SNI proxy ports set to: %v", ports)
			}
		} else {
			log.Printf("SNI proxy ports using default: %v", proxy.proxyPorts)
		}
	}

	return proxy
}

func (p *TLSProxy) Start() error {
	if !p.enabled {
		return nil
	}

	for _, port := range p.proxyPorts {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", p.proxyIP, port))
		if err != nil {
			log.Printf("Failed to start TLS proxy on port %d: %v", port, err)
			continue
		}

		p.listeners = append(p.listeners, listener)
		log.Printf("TLS SNI proxy listening on %s:%d", p.proxyIP, port)

		go func(l net.Listener, port int) {
			defer l.Close()
			for {
				conn, err := l.Accept()
				if err != nil {
					log.Printf("TLS proxy accept error on port %d: %v", port, err)
					return
				}
				go p.handleConnection(conn, port)
			}
		}(listener, port)
	}

	if len(p.listeners) == 0 {
		return fmt.Errorf("failed to start TLS proxy on any configured ports")
	}

	return nil
}

func (p *TLSProxy) handleConnection(clientConn net.Conn, port int) {
	defer clientConn.Close()

	clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
	if err != nil {
		log.Printf("Failed to parse client address: %v", err)
		return
	}

	sni, originalData, err := p.extractSNI(clientConn)
	if err != nil {
		log.Printf("Failed to extract SNI from client %s: %v", clientIP, err)
		return
	}

	if sni == "" {
		log.Printf("No SNI found in TLS handshake from client %s", clientIP)
		return
	}

	mapping, err := p.getSNIMapping(clientIP, sni)
	if err != nil {
		log.Printf("Failed to get SNI mapping for %s->%s: %v", clientIP, sni, err)
		return
	}

	if mapping == nil {
		log.Printf("No valid SNI mapping found for client %s requesting %s", clientIP, sni)
		return
	}

	log.Printf("SNI verification successful: client %s requesting %s, forwarding to %s:%d", 
		clientIP, sni, mapping.RealIP, port)

	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", mapping.RealIP, port))
	if err != nil {
		log.Printf("Failed to connect to target %s:%d: %v", mapping.RealIP, port, err)
		return
	}
	defer targetConn.Close()

	if _, err := targetConn.Write(originalData); err != nil {
		log.Printf("Failed to forward initial data to target: %v", err)
		return
	}

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

func (p *TLSProxy) extractSNI(conn net.Conn) (string, []byte, error) {
	buffer := make([]byte, 4096)
	
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", nil, err
	}
	conn.SetReadDeadline(time.Time{})

	originalData := buffer[:n]
	sni := p.parseSNIFromTLSData(originalData)
	
	return sni, originalData, nil
}

func (p *TLSProxy) parseSNIFromTLSData(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	if data[0] != 0x16 {
		return ""
	}

	if len(data) < 9 {
		return ""
	}

	recordLength := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLength {
		return ""
	}

	handshakeType := data[5]
	if handshakeType != 0x01 {
		return ""
	}

	if len(data) < 43 {
		return ""
	}

	sessionIDLength := int(data[43])
	pos := 44 + sessionIDLength

	if len(data) < pos+2 {
		return ""
	}

	cipherSuitesLength := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLength

	if len(data) < pos+1 {
		return ""
	}

	compressionMethodsLength := int(data[pos])
	pos += 1 + compressionMethodsLength

	if len(data) < pos+2 {
		return ""
	}

	extensionsLength := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	endPos := pos + extensionsLength
	if len(data) < endPos {
		return ""
	}

	for pos < endPos {
		if len(data) < pos+4 {
			break
		}

		extensionType := int(data[pos])<<8 | int(data[pos+1])
		extensionLength := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extensionType == 0x0000 {
			return p.parseSNIExtension(data[pos : pos+extensionLength])
		}

		pos += extensionLength
	}

	return ""
}

func (p *TLSProxy) parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	listLength := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLength {
		return ""
	}

	pos := 2
	for pos < len(data) {
		if len(data) < pos+3 {
			break
		}

		nameType := data[pos]
		nameLength := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if nameType == 0x00 && len(data) >= pos+nameLength {
			return string(data[pos : pos+nameLength])
		}

		pos += nameLength
	}

	return ""
}

func (p *TLSProxy) getSNIMapping(clientIP, sni string) (*SNIMapping, error) {
	if p.redisClient == nil {
		return nil, fmt.Errorf("Redis client not available")
	}

	pattern := fmt.Sprintf("rules|%s|*|%s.*", clientIP, sni)
	keys, err := p.redisClient.Keys(p.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		parts := strings.Split(key, "|")
		if len(parts) >= 4 {
			clientIPFromKey := parts[1]
			realIP := parts[2]
			domainFromKey := strings.TrimSuffix(parts[3], ".")

			if clientIPFromKey == clientIP && p.domainMatches(sni, domainFromKey) {
				exists, err := p.redisClient.Exists(p.ctx, key).Result()
				if err == nil && exists > 0 {
					return &SNIMapping{
						OriginalDomain: domainFromKey,
						RealIP:         realIP,
						ClientIP:       clientIP,
						CreatedAt:      time.Now(),
					}, nil
				}
			}
		}
	}

	return nil, nil
}

func (p *TLSProxy) domainMatches(sni, domain string) bool {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if sni == domain {
		return true
	}

	if strings.HasSuffix(sni, "."+domain) {
		return true
	}

	return false
}

func (p *TLSProxy) ModifyDNSResponse(clientIP, domain, realIP string) string {
	if !p.enabled {
		return realIP
	}

	// Check if SNI verification is enabled for this specific client
	if !p.clientConfig.isSNIEnabledForClient(clientIP) {
		return realIP
	}

	key := fmt.Sprintf("sni_mapping|%s|%s", clientIP, domain)

	if p.redisClient != nil {
		mappingJSON := fmt.Sprintf(`{"real_ip":"%s","domain":"%s"}`, realIP, domain)
		p.redisClient.Set(p.ctx, key, mappingJSON, 1*time.Hour)
	}

	log.Printf("DNS response modified: %s -> %s (real: %s) for client %s", 
		domain, p.proxyIP, realIP, clientIP)
	
	return p.proxyIP
}

func (p *TLSProxy) IsEnabled() bool {
	return p.enabled
}

func (p *TLSProxy) IsEnabledForClient(clientIP string) bool {
	if !p.enabled {
		return false
	}
	return p.clientConfig.isSNIEnabledForClient(clientIP)
}