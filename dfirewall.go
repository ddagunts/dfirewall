// Copyright 2025 Dmitry Dagunts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// a DNS proxy with support for injection of client/response states into Redis
// and execution of scripts, providing options to building a "deny-by-default" egress firewall

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
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

	redisEnv := os.Getenv("REDIS")
	if redisEnv == "" {
		log.Printf("Missing REDIS env var, this isn't meant to be run without Redis")
	}

	var redisClient *redis.Client
	if redisEnv != "" {
		opt, err := redis.ParseURL(redisEnv)
		if err != nil {
			log.Fatalf("Failed to parse Redis URL: %v", err)
		}
		redisClient = redis.NewClient(opt)

		ctx := context.Background()
		err = redisClient.Set(ctx, "ConnTest", "succeeded", 0).Err()
		if err != nil {
			log.Printf("Unable to add key to Redis! This isn't meant to be run without Redis:\n %s", err.Error())
		}
		val, err := redisClient.Get(ctx, "ConnTest").Result()
		if err != nil {
			log.Printf("Unable to read key from Redis! This isn't meant to be run without Redis:\n %s", err.Error())
		}
		_, err = redisClient.Del(ctx, "ConnTest").Result()
		if err != nil {
			log.Printf("Unable to delete key from Redis! This isn't meant to be run without Redis:\n %s", err.Error())
		}
		log.Printf("Redis connection %s", val)

		setupWebUI(redisClient)
	}

	for i := range routes {
		err := RegisterWithRedis(routes[i], redisClient)
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
