// Copyright 2025 Dmitry Dagunts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// a DNS proxy with support for injection of client/response states into Redis
// and execution of scripts, providing options to building a "deny-by-default" egress firewall

package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
)

var routes = []Route{{Zone: "."}}

func main() {
	port := 53
	portEnv := os.Getenv("PORT")
	if value, err := strconv.Atoi(portEnv); err == nil {
		port = value
	} else {
		log.Printf("listening on port 53, set PORT env var to change")
	}

	for i := range routes {
		err := Register(routes[i])
		if err != nil {
			log.Fatalf("Failed to register route for: %q: %s", routes[i].Zone, err)
		}
	}

	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set UDP listener: %s", err.Error())
		}
	}()

	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "tcp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set TCP listener: %s", err.Error())
		}
	}()

	log.Printf("dfirewall started")

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping", s)
}
