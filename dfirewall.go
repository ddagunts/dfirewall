// Copyright 2025 Dmitry Dagunts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// a DNS proxy with support for injection of client/response states into Redis
// and execution of scripts, providing options to building a "deny-by-default" egress firewall

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var routes = []Route{{Zone: "."}}

// validateBindIP validates an IP address for binding to network interfaces
func validateBindIP(ip string) error {
	if ip == "" {
		return nil // Empty string is valid (binds to all interfaces)
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	// Check if the IP is available on the system
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: could not enumerate network interfaces: %v", err)
		return nil // Don't fail on interface enumeration error
	}
	
	// For 0.0.0.0 or :: (bind to all interfaces), no further validation needed
	if parsedIP.IsUnspecified() {
		return nil
	}
	
	// Check if the IP exists on any interface
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			var ifaceIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifaceIP = v.IP
			case *net.IPAddr:
				ifaceIP = v.IP
			}
			
			if ifaceIP != nil && ifaceIP.Equal(parsedIP) {
				return nil // Found matching interface
			}
		}
	}
	
	log.Printf("Warning: IP address %s not found on any network interface", ip)
	return nil // Don't fail if IP not found - let the bind operation handle it
}

// daemonize forks the process to run in background
func daemonize(pidFile string) error {
	// Fork the process
	pid := os.Getpid()
	
	// Create new process group
	if _, err := syscall.Setsid(); err != nil {
		return fmt.Errorf("failed to create new session: %v", err)
	}
	
	// Change working directory to root to avoid locking any directory
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("failed to change directory to /: %v", err)
	}
	
	// Redirect stdin, stdout, stderr to /dev/null
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %v", err)
	}
	defer devNull.Close()
	
	// Only redirect if not in debug mode
	if os.Getenv("DEBUG") == "" {
		os.Stdin = devNull
		os.Stdout = devNull 
		os.Stderr = devNull
	}
	
	// Write PID file if specified
	if pidFile != "" {
		if err := writePIDFile(pidFile, pid); err != nil {
			return fmt.Errorf("failed to write PID file: %v", err)
		}
	}
	
	log.Printf("dfirewall daemonized with PID %d", pid)
	return nil
}

// writePIDFile writes the process ID to a file
func writePIDFile(pidFile string, pid int) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create PID file directory %s: %v", dir, err)
	}
	
	// Write PID to file
	file, err := os.Create(pidFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	_, err = fmt.Fprintf(file, "%d\n", pid)
	return err
}

// removePIDFile removes the PID file on shutdown
func removePIDFile(pidFile string) {
	if pidFile != "" {
		if err := os.Remove(pidFile); err != nil {
			log.Printf("Warning: failed to remove PID file %s: %v", pidFile, err)
		}
	}
}

func main() {
	// Check for daemon mode and PID file configuration
	daemonMode := strings.ToLower(os.Getenv("DAEMON")) == "true" || os.Getenv("DAEMON") == "1"
	pidFile := os.Getenv("PID_FILE")
	
	// If daemon mode is requested, daemonize the process
	if daemonMode {
		if err := daemonize(pidFile); err != nil {
			log.Fatalf("Failed to daemonize: %v", err)
		}
		
		// Ensure PID file is removed on exit
		if pidFile != "" {
			defer removePIDFile(pidFile)
		}
	}
	
	port := 53
	portEnv := os.Getenv("PORT")
	if value, err := strconv.Atoi(portEnv); err == nil {
		port = value
	} else {
		log.Printf("listening on port 53, set PORT env var to change")
	}

	// DNS interface binding configuration
	dnsBindIP := os.Getenv("DNS_BIND_IP")
	if dnsBindIP == "" {
		dnsBindIP = "" // Default to bind to all interfaces (0.0.0.0)
		log.Printf("DNS will bind to all interfaces, set DNS_BIND_IP to restrict")
	} else {
		if err := validateBindIP(dnsBindIP); err != nil {
			log.Fatalf("Invalid DNS_BIND_IP: %v", err)
		}
		log.Printf("DNS will bind to interface: %s", dnsBindIP)
	}

	// Construct DNS server address
	dnsAddr := dnsBindIP + ":" + strconv.Itoa(port)

	for i := range routes {
		err := Register(routes[i])
		if err != nil {
			log.Fatalf("Failed to register route for: %q: %s", routes[i].Zone, err)
		}
	}

	go func() {
		srv := &dns.Server{Addr: dnsAddr, Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set UDP listener on %s: %s", dnsAddr, err.Error())
		}
	}()

	go func() {
		srv := &dns.Server{Addr: dnsAddr, Net: "tcp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set TCP listener on %s: %s", dnsAddr, err.Error())
		}
	}()

	if daemonMode {
		log.Printf("dfirewall started in daemon mode")
	} else {
		log.Printf("dfirewall started")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%v) received, stopping...", s)
	
	// Gracefully stop cache cleanup
	stopCacheCleanup()
	
	// Remove PID file if we're running as daemon
	if daemonMode && pidFile != "" {
		removePIDFile(pidFile)
	}
	
	log.Printf("dfirewall stopped")
	os.Exit(0)
}
