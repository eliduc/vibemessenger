#!/bin/bash
# ============================================================================
# VibeMessenger — Secrets Rotation Script (v3.11.9)
# ============================================================================
# Run on the server: bash rotate_secrets.sh
# 
# What this does:
# 1. Generates new SECRET_KEY (JWT signing) — all users will need to re-login
# 2. Generates new TOTP_ENCRYPTION_KEY for envelope encryption of 2FA secrets
# 3. Adds missing .gitignore entries for *.pem, *.key, .env
# 4. Shows commands to rotate DB_PASSWORD (manual — requires PostgreSQL ALTER)
#
# What this does NOT do (manual steps):
# - Rotate DB_PASSWORD (requires ALTER USER in PostgreSQL)
# - Rotate TURN credentials (requires update on metered.ca dashboard)
# - Generate new VAPID keys (breaks existing push subscriptions)
# - Generate new TLS certs (managed separately)
# ============================================================================

set -e

STAGE_DIR="$HOME/vibemessenger-stage"
ENV_FILE="$STAGE_DIR/.env"

echo "=== VibeMessenger Secrets Rotation ==="
echo ""

# Check we're in the right place
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found"
    exit 1
fi

# Backup current .env
cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo "✓ Backed up .env"

# 1. Generate new SECRET_KEY
NEW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "✓ Generated new SECRET_KEY"

# 2. Generate TOTP encryption key
NEW_TOTP_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "✓ Generated new TOTP_ENCRYPTION_KEY"

# 3. Update .env — replace SECRET_KEY
if grep -q "^SECRET_KEY=" "$ENV_FILE"; then
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$NEW_SECRET_KEY|" "$ENV_FILE"
    echo "✓ Updated SECRET_KEY in .env"
else
    echo "SECRET_KEY=$NEW_SECRET_KEY" >> "$ENV_FILE"
    echo "✓ Added SECRET_KEY to .env"
fi

# 4. Add TOTP encryption key if not present
if grep -q "^MESSENGER_TOTP_ENCRYPTION_KEY=" "$ENV_FILE"; then
    sed -i "s|^MESSENGER_TOTP_ENCRYPTION_KEY=.*|MESSENGER_TOTP_ENCRYPTION_KEY=$NEW_TOTP_KEY|" "$ENV_FILE"
    echo "✓ Updated MESSENGER_TOTP_ENCRYPTION_KEY in .env"
else
    echo "" >> "$ENV_FILE"
    echo "# v3.11.9: Envelope encryption for TOTP secrets" >> "$ENV_FILE"
    echo "MESSENGER_TOTP_ENCRYPTION_KEY=$NEW_TOTP_KEY" >> "$ENV_FILE"
    echo "✓ Added MESSENGER_TOTP_ENCRYPTION_KEY to .env"
fi

# 5. Update .gitignore
GITIGNORE="$STAGE_DIR/.gitignore"
if [ -f "$GITIGNORE" ]; then
    # Add security entries if missing
    for pattern in "*.pem" "*.key" "*.crt" ".env" ".env.*" "certs/" "server/data/vapid*"; do
        if ! grep -qF "$pattern" "$GITIGNORE"; then
            echo "$pattern" >> "$GITIGNORE"
            echo "✓ Added '$pattern' to .gitignore"
        fi
    done
else
    cat > "$GITIGNORE" << 'GITIGNORE'
# Security — never commit
*.pem
*.key
*.crt
.env
.env.*
certs/
server/data/vapid*

# Python
__pycache__/
*.pyc
*.egg-info/

# Docker
data/
GITIGNORE
    echo "✓ Created .gitignore"
fi

echo ""
echo "=== Done ==="
echo ""
echo "⚠️  SECRET_KEY rotated — all users will need to re-login."
echo ""
echo "Next steps:"
echo "  1. Rebuild and restart:"
echo "     cd $STAGE_DIR && docker compose build --no-cache messenger && docker compose up -d"
echo ""
echo "  2. (Optional) Rotate DB password manually:"
echo "     docker compose exec postgres psql -U messenger -c \"ALTER USER messenger PASSWORD 'NEW_PASSWORD';\""
echo "     Then update DB_PASSWORD in .env and restart."
echo ""
echo "  3. (Optional) Rotate TURN credentials on metered.ca dashboard"
echo "     Then update MESSENGER_TURN_USERNAME/MESSENGER_TURN_CREDENTIAL in .env"
echo ""
echo "  4. Verify: docker compose logs --tail=20 messenger"
