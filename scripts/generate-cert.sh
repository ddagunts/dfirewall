#!/bin/bash

# Generate self-signed SSL certificate for dfirewall Web UI
# Usage: ./generate-cert.sh [hostname] [output_dir]

HOSTNAME=${1:-localhost}
OUTPUT_DIR=${2:-./certs}

echo "Generating self-signed SSL certificate for: $HOSTNAME"
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate private key
openssl genrsa -out "$OUTPUT_DIR/dfirewall.key" 2048

# Generate certificate signing request
openssl req -new -key "$OUTPUT_DIR/dfirewall.key" -out "$OUTPUT_DIR/dfirewall.csr" -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=$HOSTNAME"

# Generate self-signed certificate (valid for 1 year)
openssl x509 -req -in "$OUTPUT_DIR/dfirewall.csr" -signkey "$OUTPUT_DIR/dfirewall.key" -out "$OUTPUT_DIR/dfirewall.crt" -days 365

# Set appropriate permissions
chmod 600 "$OUTPUT_DIR/dfirewall.key"
chmod 644 "$OUTPUT_DIR/dfirewall.crt"

# Clean up CSR
rm "$OUTPUT_DIR/dfirewall.csr"

echo "Certificate files generated:"
echo "  Private key: $OUTPUT_DIR/dfirewall.key"
echo "  Certificate: $OUTPUT_DIR/dfirewall.crt"
echo ""
echo "To use with dfirewall:"
echo "  export WEBUI_HTTPS_ENABLED=true"
echo "  export WEBUI_CERT_FILE=$OUTPUT_DIR/dfirewall.crt"
echo "  export WEBUI_KEY_FILE=$OUTPUT_DIR/dfirewall.key"