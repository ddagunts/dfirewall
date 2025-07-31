#!/bin/bash

# dfirewall domain-specific validation script example
# This script validates domain names and returns 0 (allow) or 1 (block)

DOMAIN="$1"
TYPE="$2"

if [ -z "$DOMAIN" ]; then
    echo "ERROR: No domain provided" >&2
    exit 1
fi

echo "Validating domain: $DOMAIN"

# Example domain-specific validation logic

# Block known malicious domains (you could load this from a file)
BLOCKED_DOMAINS="malware.com phishing.net scam.org evil.com"
for blocked in $BLOCKED_DOMAINS; do
    if [ "$DOMAIN" = "$blocked" ] || echo "$DOMAIN" | grep -q "\.$blocked$"; then
        echo "BLOCK: Domain is in blocked list"
        exit 1
    fi
done

# Block domains with suspicious length
SUBDOMAIN=$(echo "$DOMAIN" | cut -d'.' -f1)
if [ ${#SUBDOMAIN} -gt 25 ]; then
    echo "BLOCK: Subdomain too long (${#SUBDOMAIN} chars)"
    exit 1
fi

# Block domains with too many subdomains (potential tunneling)
SUBDOMAIN_COUNT=$(echo "$DOMAIN" | tr '.' '\n' | wc -l)
if [ "$SUBDOMAIN_COUNT" -gt 5 ]; then
    echo "BLOCK: Too many subdomains ($SUBDOMAIN_COUNT)"
    exit 1
fi

# Block domains with numeric-only subdomains
if echo "$DOMAIN" | grep -q "^[0-9][0-9]*\."; then
    echo "BLOCK: Numeric subdomain detected"
    exit 1
fi

echo "ALLOW: Domain validation passed"
exit 0