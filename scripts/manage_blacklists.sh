#!/bin/bash

# Redis blacklist management script for dfirewall
# This script helps manage IP and domain blacklists in Redis

REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
IP_SET="${IP_SET:-dfirewall:blacklist:ips}"
DOMAIN_SET="${DOMAIN_SET:-dfirewall:blacklist:domains}"

function show_help() {
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  add-ip <ip>              Add IP to blacklist"
    echo "  remove-ip <ip>           Remove IP from blacklist"
    echo "  add-domain <domain>      Add domain to blacklist"
    echo "  remove-domain <domain>   Remove domain from blacklist"
    echo "  list-ips                 List all blacklisted IPs"
    echo "  list-domains            List all blacklisted domains"
    echo "  load-ips <file>         Load IPs from file to Redis"
    echo "  load-domains <file>     Load domains from file to Redis"
    echo "  clear-ips               Clear all IP blacklists"
    echo "  clear-domains           Clear all domain blacklists"
    echo "  stats                   Show blacklist statistics"
    echo ""
    echo "Environment variables:"
    echo "  REDIS_HOST              Redis host (default: 127.0.0.1)"
    echo "  REDIS_PORT              Redis port (default: 6379)"
    echo "  IP_SET                  Redis set name for IPs (default: dfirewall:blacklist:ips)"
    echo "  DOMAIN_SET              Redis set name for domains (default: dfirewall:blacklist:domains)"
}

function redis_cmd() {
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" "$@"
}

case "$1" in
    "add-ip")
        if [ -z "$2" ]; then
            echo "Error: IP address required"
            exit 1
        fi
        redis_cmd SADD "$IP_SET" "$2"
        echo "Added IP $2 to blacklist"
        ;;
    
    "remove-ip")
        if [ -z "$2" ]; then
            echo "Error: IP address required"
            exit 1
        fi
        redis_cmd SREM "$IP_SET" "$2"
        echo "Removed IP $2 from blacklist"
        ;;
    
    "add-domain")
        if [ -z "$2" ]; then
            echo "Error: Domain required"
            exit 1
        fi
        # Convert to lowercase for consistency
        domain=$(echo "$2" | tr '[:upper:]' '[:lower:]')
        redis_cmd SADD "$DOMAIN_SET" "$domain"
        echo "Added domain $domain to blacklist"
        ;;
    
    "remove-domain")
        if [ -z "$2" ]; then
            echo "Error: Domain required"
            exit 1
        fi
        domain=$(echo "$2" | tr '[:upper:]' '[:lower:]')
        redis_cmd SREM "$DOMAIN_SET" "$domain"
        echo "Removed domain $domain from blacklist"
        ;;
    
    "list-ips")
        echo "Blacklisted IPs:"
        redis_cmd SMEMBERS "$IP_SET"
        ;;
    
    "list-domains")
        echo "Blacklisted domains:"
        redis_cmd SMEMBERS "$DOMAIN_SET"
        ;;
    
    "load-ips")
        if [ -z "$2" ] || [ ! -f "$2" ]; then
            echo "Error: Valid file path required"
            exit 1
        fi
        count=0
        while IFS= read -r line; do
            # Skip empty lines and comments
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                redis_cmd SADD "$IP_SET" "$line"
                ((count++))
            fi
        done < "$2"
        echo "Loaded $count IPs from $2"
        ;;
    
    "load-domains")
        if [ -z "$2" ] || [ ! -f "$2" ]; then
            echo "Error: Valid file path required"
            exit 1
        fi
        count=0
        while IFS= read -r line; do
            # Skip empty lines and comments
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                domain=$(echo "$line" | tr '[:upper:]' '[:lower:]')
                redis_cmd SADD "$DOMAIN_SET" "$domain"
                ((count++))
            fi
        done < "$2"
        echo "Loaded $count domains from $2"
        ;;
    
    "clear-ips")
        redis_cmd DEL "$IP_SET"
        echo "Cleared all IP blacklists"
        ;;
    
    "clear-domains")
        redis_cmd DEL "$DOMAIN_SET"
        echo "Cleared all domain blacklists"
        ;;
    
    "stats")
        ip_count=$(redis_cmd SCARD "$IP_SET")
        domain_count=$(redis_cmd SCARD "$DOMAIN_SET")
        echo "Blacklist statistics:"
        echo "  IPs: $ip_count"
        echo "  Domains: $domain_count"
        echo "  Redis sets: $IP_SET, $DOMAIN_SET"
        ;;
    
    "help"|"-h"|"--help"|"")
        show_help
        ;;
    
    *)
        echo "Error: Unknown command '$1'"
        echo ""
        show_help
        exit 1
        ;;
esac