#!/bin/bash

# SSH Host Key Fingerprint Utility for dfirewall
# This script helps you get the SSH host key fingerprint for secure log collection

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <hostname> [port]"
    echo "Examples:"
    echo "  $0 server.example.com"
    echo "  $0 server.example.com 2222"
    echo ""
    echo "This script will:"
    echo "1. Connect to the SSH server and get its host key"
    echo "2. Show the SHA256 fingerprint for use in dfirewall log collection config"
    echo "3. Optionally add the host to your known_hosts file"
    exit 1
fi

HOSTNAME="$1"
PORT="${2:-22}"

echo "Getting SSH host key fingerprint for $HOSTNAME:$PORT..."
echo ""

# Get the host key using ssh-keyscan
echo "Scanning for host keys..."
HOST_KEYS=$(ssh-keyscan -p "$PORT" "$HOSTNAME" 2>/dev/null)

if [ -z "$HOST_KEYS" ]; then
    echo "ERROR: Could not retrieve host keys from $HOSTNAME:$PORT"
    echo "Please check that the host is reachable and SSH is running on port $PORT"
    exit 1
fi

echo "Found host keys:"
echo "$HOST_KEYS"
echo ""

# Calculate fingerprints for each key type
echo "SHA256 Fingerprints:"
echo "$HOST_KEYS" | while read line; do
    if [ -n "$line" ]; then
        # Extract the key part (third field)
        KEY=$(echo "$line" | awk '{print $3}')
        KEY_TYPE=$(echo "$line" | awk '{print $2}')
        
        # Calculate SHA256 fingerprint
        FINGERPRINT=$(echo "$line" | ssh-keygen -lf - | awk '{print $2}')
        
        echo "  $KEY_TYPE: $FINGERPRINT"
        
        # Also show the base64 part (without SHA256: prefix) for dfirewall config
        BASE64_PART=$(echo "$FINGERPRINT" | sed 's/^SHA256://')
        echo "    For dfirewall config: \"$BASE64_PART\""
        echo ""
    fi
done

echo ""
echo "To use in dfirewall log collection configuration:"
echo "{"
echo "  \"host_key_verification\": \"fingerprint\","
echo "  \"host_key_fingerprint\": \"<BASE64_PART_FROM_ABOVE>\""
echo "}"
echo ""

# Ask if user wants to add to known_hosts
read -p "Add these keys to your known_hosts file? (y/N): " ADD_TO_KNOWN_HOSTS

if [ "$ADD_TO_KNOWN_HOSTS" = "y" ] || [ "$ADD_TO_KNOWN_HOSTS" = "Y" ]; then
    KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"
    
    # Create .ssh directory if it doesn't exist
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    
    # Remove any existing entries for this host
    if [ -f "$KNOWN_HOSTS_FILE" ]; then
        ssh-keygen -R "$HOSTNAME" -f "$KNOWN_HOSTS_FILE" 2>/dev/null || true
        if [ "$PORT" != "22" ]; then
            ssh-keygen -R "[$HOSTNAME]:$PORT" -f "$KNOWN_HOSTS_FILE" 2>/dev/null || true
        fi
    fi
    
    # Add the new keys
    echo "$HOST_KEYS" >> "$KNOWN_HOSTS_FILE"
    chmod 600 "$KNOWN_HOSTS_FILE"
    
    echo "Host keys added to $KNOWN_HOSTS_FILE"
    echo ""
    echo "You can now use:"
    echo "{"
    echo "  \"host_key_verification\": \"known_hosts\""
    echo "}"
    echo "in your dfirewall log collection configuration."
else
    echo "Host keys not added to known_hosts file."
fi

echo ""
echo "Security note: Always verify these fingerprints through a secure channel"
echo "before using them in production environments."