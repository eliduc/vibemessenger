#!/bin/bash
# VibeMessenger v3.11.0 PQXDH Stage Deployment
# Post-Quantum Cryptography (ML-KEM-768 hybrid key exchange)
#
# Run from: ~/vibemessenger-stage/

set -e
echo "=== VibeMessenger v3.11.0 PQXDH Stage Deploy ==="

# 1. Database migration - add pq_kem_public_key column
echo ""
echo "Step 1: Database migration..."
docker exec messenger-db-stage psql -U messenger -d messenger -c \
    "ALTER TABLE key_bundles ADD COLUMN IF NOT EXISTS pq_kem_public_key TEXT;"
echo "  ✓ Column pq_kem_public_key added"

# Verify
docker exec messenger-db-stage psql -U messenger -d messenger -c \
    "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='key_bundles' AND column_name='pq_kem_public_key';"

# 2. Restart containers (picks up server code changes)
echo ""
echo "Step 2: Restarting containers..."
docker compose restart
echo "  ✓ Containers restarted"

# 3. Wait for health check
echo ""
echo "Step 3: Waiting for API health..."
sleep 5
docker exec messenger-api-stage python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>/dev/null && echo "  ✓ API healthy" || echo "  ⚠ API not ready yet"

# 4. Verify PQ-KEM file served
echo ""
echo "Step 4: Verify pq-kem.js..."
ls -la web-client/pq-kem.js
echo "  ✓ pq-kem.js present ($(wc -c < web-client/pq-kem.js) bytes)"

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Testing checklist:"
echo "  1. Open stage site in browser"
echo "  2. Open DevTools Console"
echo "  3. Check: PQKEM.isAvailable() → true"
echo "  4. Check: VibeCrypto.hasPqKem() → true"
echo "  5. Reset E2EE keys (Settings → Reset E2EE)"
echo "  6. Check new bundle has pq_kem_public_key in DB:"
echo "     docker exec messenger-db-stage psql -U messenger -d messenger -c \"SELECT user_id, pq_kem_public_key IS NOT NULL as has_pq FROM key_bundles;\""
echo "  7. Exchange messages between 2 users → should use PQXDH (v:2)"
echo "  8. Console should show [PQXDH-INIT] and [PQXDH-PROC] logs"
