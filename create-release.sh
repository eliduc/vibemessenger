#!/bin/bash
# VibeMessenger Release Archive Creator
# Creates a distribution archive WITHOUT any secrets/private keys

set -e

VERSION="${1:-v3.1}"
RELEASE_NAME="vibemessenger-release-${VERSION}"
TEMP_DIR="/tmp/${RELEASE_NAME}"
ARCHIVE_PATH="$(pwd)/${RELEASE_NAME}.tar.gz"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   VibeMessenger Release Creator ${VERSION}${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"

# Clean up previous temp dir if exists
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

echo -e "${YELLOW}► Creating release structure...${NC}"

# Copy server files (excluding secrets)
mkdir -p "$TEMP_DIR/server/app"
cp -r server/app/*.py "$TEMP_DIR/server/app/" 2>/dev/null || true
cp -r server/app/api "$TEMP_DIR/server/app/"
cp -r server/app/models "$TEMP_DIR/server/app/"
cp -r server/app/services "$TEMP_DIR/server/app/"
cp -r server/app/crypto "$TEMP_DIR/server/app/" 2>/dev/null || true
cp server/Dockerfile "$TEMP_DIR/server/"
cp server/requirements.txt "$TEMP_DIR/server/"

# Copy web client (no secrets here)
mkdir -p "$TEMP_DIR/web-client"
cp web-client/app.js "$TEMP_DIR/web-client/"
cp web-client/index.html "$TEMP_DIR/web-client/"
cp web-client/style.css "$TEMP_DIR/web-client/"
cp web-client/sw.js "$TEMP_DIR/web-client/"
cp web-client/manifest.json "$TEMP_DIR/web-client/"
cp web-client/icon-*.png "$TEMP_DIR/web-client/" 2>/dev/null || true
cp web-client/badge-*.png "$TEMP_DIR/web-client/" 2>/dev/null || true

# Copy config files (but NOT certs)
mkdir -p "$TEMP_DIR/config"
cp config/nginx.conf "$TEMP_DIR/config/"

# Copy certs directory structure with placeholder
mkdir -p "$TEMP_DIR/certs"
cat > "$TEMP_DIR/certs/README.md" << 'EOF'
# SSL Certificates

This directory should contain:
- `server.crt` - SSL certificate
- `server.key` - SSL private key (KEEP SECRET!)

Generate self-signed certificate:
```bash
../generate-keys.sh
```

For production, use Let's Encrypt or another CA.
EOF

# Copy docs
mkdir -p "$TEMP_DIR/docs"
cp docs/*.md "$TEMP_DIR/docs/" 2>/dev/null || true
cp docs/*.html "$TEMP_DIR/docs/" 2>/dev/null || true

# Copy scripts and config files
cp docker-compose.yml "$TEMP_DIR/"
cp .gitignore "$TEMP_DIR/"
cp generate-keys.sh "$TEMP_DIR/"
cp backup.sh "$TEMP_DIR/"
cp restore.sh "$TEMP_DIR/"
cp backup-cleanup.sh "$TEMP_DIR/" 2>/dev/null || true
cp README.md "$TEMP_DIR/" 2>/dev/null || true

# Create .env.example (without actual secrets)
cat > "$TEMP_DIR/.env.example" << 'EOF'
# VibeMessenger Environment Configuration
# Copy this file to .env and fill in your values

# ======================
# DATABASE
# ======================
# Generate with: openssl rand -hex 16
DB_PASSWORD=CHANGE_THIS_GENERATE_RANDOM_PASSWORD

# ======================
# SECURITY (CRITICAL!)
# ======================
# Generate with: openssl rand -hex 32
# Application will NOT start with insecure key!
MESSENGER_SECRET_KEY=CHANGE_THIS_GENERATE_WITH_openssl_rand_hex_32

# ======================
# VAPID (Push Notifications)
# ======================
# Generate with: ./generate-keys.sh
MESSENGER_VAPID_PUBLIC_KEY=YOUR_VAPID_PUBLIC_KEY_HERE

# ======================
# TURN SERVER (WebRTC Calls)
# ======================
# Get free credentials at: https://www.metered.ca/stun-turn
MESSENGER_TURN_ENABLED=true
MESSENGER_TURN_SERVER_URL=global.relay.metered.ca
MESSENGER_TURN_SERVER_PORT=443
MESSENGER_TURN_USERNAME=your_metered_username
MESSENGER_TURN_CREDENTIAL=your_metered_credential
MESSENGER_STUN_SERVER_URL=stun:stun.relay.metered.ca:80

# ======================
# CORS (Optional)
# ======================
# Comma-separated list of allowed origins
# Leave empty for same-origin only (recommended for security)
MESSENGER_CORS_ORIGINS=

# ======================
# DEBUG (Development only - NEVER enable in production!)
# ======================
MESSENGER_DEBUG=false
EOF

# Create data directory structure
mkdir -p "$TEMP_DIR/data/uploads"
mkdir -p "$TEMP_DIR/data/avatars"
mkdir -p "$TEMP_DIR/data/group_avatars"

# Add .gitkeep files
touch "$TEMP_DIR/data/uploads/.gitkeep"
touch "$TEMP_DIR/data/avatars/.gitkeep"
touch "$TEMP_DIR/data/group_avatars/.gitkeep"

echo -e "${GREEN}  ✓ Files copied${NC}"

# Remove any accidentally included secrets
echo -e "${YELLOW}► Removing any secrets...${NC}"
find "$TEMP_DIR" -name "*.key" -delete 2>/dev/null || true
find "$TEMP_DIR" -name "*private*.pem" -delete 2>/dev/null || true
find "$TEMP_DIR" -name "vapid_private.pem" -delete 2>/dev/null || true
find "$TEMP_DIR" -name ".env" -not -name ".env.example" -delete 2>/dev/null || true
find "$TEMP_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$TEMP_DIR" -name "*.pyc" -delete 2>/dev/null || true
find "$TEMP_DIR" -name "*.bak" -delete 2>/dev/null || true
echo -e "${GREEN}  ✓ Secrets removed${NC}"

# Create archive
echo -e "${YELLOW}► Creating archive...${NC}"
tar -czf "$ARCHIVE_PATH" -C /tmp "$RELEASE_NAME"
ARCHIVE_SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
echo -e "${GREEN}  ✓ Archive created: $ARCHIVE_SIZE${NC}"

# Verify no secrets in archive
echo -e "${YELLOW}► Verifying archive is clean...${NC}"
if tar -tzf "$ARCHIVE_PATH" | grep -E "\.key$|private.*\.pem$|vapid_private\.pem$|^[^/]*/.env$" | grep -v ".env.example"; then
    echo -e "${RED}WARNING: Archive may contain secrets!${NC}"
    exit 1
else
    echo -e "${GREEN}  ✓ No secrets found in archive${NC}"
fi

# Cleanup
rm -rf "$TEMP_DIR"
echo -e "${GREEN}  ✓ Temp files cleaned${NC}"

# Done
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Release archive created successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "   File: ${ARCHIVE_PATH}"
echo -e "   Size: ${ARCHIVE_SIZE}"
echo ""
echo -e "${YELLOW}Contents:${NC}"
tar -tzf "$ARCHIVE_PATH" | head -20
echo "   ..."
echo ""
echo -e "${YELLOW}To install on a new system:${NC}"
echo "   1. tar -xzf $RELEASE_NAME.tar.gz"
echo "   2. cd $RELEASE_NAME"
echo "   3. ./generate-keys.sh"
echo "   4. cp .env.example .env && nano .env"
echo "   5. docker compose up -d"
