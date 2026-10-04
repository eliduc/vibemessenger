#!/bin/bash
# Generate new SSL and VAPID keys for VibeMessenger
# Run this script after cloning the repository

set -e

echo "=== VibeMessenger Key Generation ==="
echo ""

# Create directories
mkdir -p certs
mkdir -p server

# 1. Generate SSL certificate
echo "[1/2] Generating SSL certificate..."
if [ -f certs/server.key ]; then
    read -p "SSL key already exists. Regenerate? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Skipping SSL generation."
    else
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout certs/server.key \
            -out certs/server.crt \
            -subj "/CN=localhost/O=VibeMessenger/C=US"
        echo "✓ SSL certificate generated: certs/server.crt, certs/server.key"
    fi
else
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/server.key \
        -out certs/server.crt \
        -subj "/CN=localhost/O=VibeMessenger/C=US"
    echo "✓ SSL certificate generated: certs/server.crt, certs/server.key"
fi

# 2. Generate VAPID keys for push notifications
echo ""
echo "[2/2] Generating VAPID keys for push notifications..."
if [ -f server/vapid_private.pem ]; then
    read -p "VAPID key already exists. Regenerate? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Skipping VAPID generation."
    else
        # Generate EC private key
        openssl ecparam -genkey -name prime256v1 -out server/vapid_private.pem
        
        # Extract public key and convert to base64url
        VAPID_PUBLIC=$(openssl ec -in server/vapid_private.pem -pubout -outform DER 2>/dev/null | tail -c 65 | base64 | tr '/+' '_-' | tr -d '=')
        
        echo "✓ VAPID keys generated"
        echo ""
        echo "Add this to your .env file:"
        echo "MESSENGER_VAPID_PUBLIC_KEY=$VAPID_PUBLIC"
    fi
else
    # Generate EC private key
    openssl ecparam -genkey -name prime256v1 -out server/vapid_private.pem
    
    # Also copy to root for docker-compose mount
    cp server/vapid_private.pem vapid_private.pem
    
    # Extract public key and convert to base64url
    VAPID_PUBLIC=$(openssl ec -in server/vapid_private.pem -pubout -outform DER 2>/dev/null | tail -c 65 | base64 | tr '/+' '_-' | tr -d '=')
    
    echo "✓ VAPID keys generated"
    echo ""
    echo "Add this to your .env file:"
    echo "MESSENGER_VAPID_PUBLIC_KEY=$VAPID_PUBLIC"
fi

echo ""
echo "=== Key generation complete ==="
echo ""
echo "IMPORTANT: These keys are in .gitignore and will NOT be committed."
echo "Keep them safe and back them up separately!"
