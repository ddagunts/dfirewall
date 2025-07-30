#!/bin/bash

# dfirewall custom validation script example
# This script receives domain/IP and type as arguments and returns 0 (allow) or 1 (block)
#
# Usage: custom_validate.sh <target> <type>
# Arguments:
#   $1 - Target (domain name or IP address)
#   $2 - Type ("domain" or "ip")
#
# Environment variables available:
#   DFIREWALL_TARGET - Same as $1
#   DFIREWALL_TYPE - Same as $2  
#   DFIREWALL_TIMESTAMP - Unix timestamp when script was called
#
# Exit codes:
#   0 - Allow (target is safe)
#   1 - Block (target should be blocked)
#   Any other exit code - Block (treated as block decision)

TARGET="$1"
TYPE="$2"

# Validate arguments
if [ -z "$TARGET" ] || [ -z "$TYPE" ]; then
    echo "ERROR: Missing required arguments" >&2
    echo "Usage: $0 <target> <type>" >&2
    exit 1
fi

# Log the validation request (optional)
echo "Validating $TYPE: $TARGET at $(date)"

# Example validation logic based on type
case "$TYPE" in
    "domain")
        # Example domain validation rules
        
        # Block domains containing "malicious" or "evil"
        if echo "$TARGET" | grep -qi -E "(malicious|evil|bad|phishing|scam)"; then
            echo "BLOCK: Domain contains suspicious keywords"
            exit 1
        fi
        
        # Block domains with suspicious patterns
        # Example: domains with more than 3 consecutive consonants
        if echo "$TARGET" | grep -q -E "[bcdfghjklmnpqrstvwxyz]{4,}"; then
            echo "BLOCK: Domain has suspicious consonant pattern"
            exit 1  
        fi
        
        # Block very long subdomains (potential DGA)
        SUBDOMAIN=$(echo "$TARGET" | cut -d'.' -f1)
        if [ ${#SUBDOMAIN} -gt 20 ]; then
            echo "BLOCK: Subdomain is suspiciously long (${#SUBDOMAIN} chars)"
            exit 1
        fi
        
        # Block domains with unusual TLDs (add your own logic)
        if echo "$TARGET" | grep -qi -E "\.(tk|ml|ga|cf)\.?$"; then
            echo "BLOCK: Suspicious TLD"
            exit 1
        fi
        
        # Allow everything else
        echo "ALLOW: Domain passed all checks"
        exit 0
        ;;
        
    "ip")
        # Example IP validation rules
        
        # Block private IP ranges that shouldn't be resolved externally
        # (Note: dfirewall already handles localhost, this is for additional private ranges)
        if echo "$TARGET" | grep -q -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
            echo "BLOCK: Private IP address in external DNS response"
            exit 1
        fi
        
        # Block known bad IP ranges (example)
        if echo "$TARGET" | grep -q -E "^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"; then
            echo "BLOCK: IP in RFC5737 test range"
            exit 1
        fi
        
        # Block IPs in certain geographic regions (example using IP range)
        # This is a simplified example - in practice you'd use a GeoIP database
        if echo "$TARGET" | grep -q -E "^(1\.2\.3\.|4\.5\.6\.)"; then
            echo "BLOCK: IP in blocked geographic region"
            exit 1
        fi
        
        # Allow everything else
        echo "ALLOW: IP passed all checks"
        exit 0
        ;;
        
    *)
        echo "ERROR: Unknown type: $TYPE" >&2
        exit 1
        ;;
esac