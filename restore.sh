#!/bin/bash
# VibeMessenger Restore Script
# Usage: ./restore.sh <backup_file.tar.gz>

set -e

# Configuration
BACKUP_FILE="$1"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR="/tmp/vibemessenger-restore-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   VibeMessenger Restore${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"

# Check arguments
if [ -z "$BACKUP_FILE" ]; then
    echo -e "${RED}Usage: $0 <backup_file.tar.gz>${NC}"
    echo ""
    echo "Available backups in /mnt/backup:"
    ls -lht /mnt/backup/vibemessenger-backup-*.tar.gz 2>/dev/null | head -10
    exit 1
fi

# Check backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    # Try with /mnt/backup prefix
    if [ -f "/mnt/backup/$BACKUP_FILE" ]; then
        BACKUP_FILE="/mnt/backup/$BACKUP_FILE"
    else
        echo -e "${RED}Error: Backup file not found: $BACKUP_FILE${NC}"
        exit 1
    fi
fi

echo -e "${YELLOW}► Backup file: $BACKUP_FILE${NC}"
BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo -e "${YELLOW}► Size: $BACKUP_SIZE${NC}"

# Confirm restore
echo ""
echo -e "${RED}WARNING: This will overwrite all current data!${NC}"
echo -e "${RED}Make sure you have a backup of current state if needed.${NC}"
echo ""
read -p "Are you sure you want to restore? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

# Check if docker is running
if ! docker ps &> /dev/null; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Create temp directory
mkdir -p "$TEMP_DIR"
echo -e "${YELLOW}► Extracting archive...${NC}"

# Extract archive
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Find the extracted directory
EXTRACTED_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "vibemessenger-backup-*" | head -1)
if [ -z "$EXTRACTED_DIR" ]; then
    echo -e "${RED}Error: Invalid backup archive structure${NC}"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo -e "${GREEN}  ✓ Archive extracted${NC}"

# Show metadata
if [ -f "$EXTRACTED_DIR/metadata.json" ]; then
    echo -e "${YELLOW}► Backup metadata:${NC}"
    cat "$EXTRACTED_DIR/metadata.json" | python3 -m json.tool 2>/dev/null || cat "$EXTRACTED_DIR/metadata.json"
    echo ""
fi

# Get database credentials from .env
cd "$PROJECT_DIR"
if [ -f .env ]; then
    source .env
fi
DB_USER="${POSTGRES_USER:-messenger}"
DB_NAME="${POSTGRES_DB:-messenger}"

# 1. Restore database
echo -e "${YELLOW}► Restoring PostgreSQL database...${NC}"
if [ -f "$EXTRACTED_DIR/database.sql" ]; then
    # Drop and recreate database
    docker compose exec -T postgres psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME};" postgres || true
    docker compose exec -T postgres psql -U "$DB_USER" -c "CREATE DATABASE ${DB_NAME};" postgres
    
    # Restore from dump
    docker compose exec -T postgres psql -U "$DB_USER" "$DB_NAME" < "$EXTRACTED_DIR/database.sql"
    echo -e "${GREEN}  ✓ Database restored${NC}"
else
    echo -e "${RED}  ✗ database.sql not found in backup${NC}"
fi

# 2. Restore user avatars
echo -e "${YELLOW}► Restoring user avatars...${NC}"
if [ -d "$EXTRACTED_DIR/avatars" ]; then
    # Clear existing avatars
    docker compose exec -T messenger rm -rf /app/data/avatars/* 2>/dev/null || true
    docker compose exec -T messenger mkdir -p /app/data/avatars
    
    # Copy new avatars
    if [ "$(ls -A "$EXTRACTED_DIR/avatars" 2>/dev/null)" ]; then
        docker compose cp "$EXTRACTED_DIR/avatars/." messenger:/app/data/avatars/
        AVATAR_COUNT=$(find "$EXTRACTED_DIR/avatars" -type f | wc -l)
        echo -e "${GREEN}  ✓ User avatars restored: $AVATAR_COUNT files${NC}"
    else
        echo -e "${GREEN}  ✓ User avatars: 0 files (empty in backup)${NC}"
    fi
else
    echo -e "${YELLOW}  - No user avatars in backup${NC}"
fi

# 3. Restore group avatars
echo -e "${YELLOW}► Restoring group avatars...${NC}"
if [ -d "$EXTRACTED_DIR/group_avatars" ]; then
    # Clear existing
    docker compose exec -T messenger rm -rf /app/data/group_avatars/* 2>/dev/null || true
    docker compose exec -T messenger mkdir -p /app/data/group_avatars
    
    # Copy new
    if [ "$(ls -A "$EXTRACTED_DIR/group_avatars" 2>/dev/null)" ]; then
        docker compose cp "$EXTRACTED_DIR/group_avatars/." messenger:/app/data/group_avatars/
        GROUP_AVATAR_COUNT=$(find "$EXTRACTED_DIR/group_avatars" -type f | wc -l)
        echo -e "${GREEN}  ✓ Group avatars restored: $GROUP_AVATAR_COUNT files${NC}"
    else
        echo -e "${GREEN}  ✓ Group avatars: 0 files (empty in backup)${NC}"
    fi
else
    echo -e "${YELLOW}  - No group avatars in backup${NC}"
fi

# 4. Restore uploaded files
echo -e "${YELLOW}► Restoring uploaded files...${NC}"
if [ -d "$EXTRACTED_DIR/uploads" ]; then
    # Clear existing
    docker compose exec -T messenger rm -rf /app/data/uploads/* 2>/dev/null || true
    docker compose exec -T messenger mkdir -p /app/data/uploads
    
    # Copy new
    if [ "$(ls -A "$EXTRACTED_DIR/uploads" 2>/dev/null)" ]; then
        docker compose cp "$EXTRACTED_DIR/uploads/." messenger:/app/data/uploads/
        UPLOAD_COUNT=$(find "$EXTRACTED_DIR/uploads" -type f | wc -l)
        echo -e "${GREEN}  ✓ Uploaded files restored: $UPLOAD_COUNT files${NC}"
    else
        echo -e "${GREEN}  ✓ Uploaded files: 0 files (empty in backup)${NC}"
    fi
else
    echo -e "${YELLOW}  - No uploaded files in backup${NC}"
fi

# 5. Restart services to apply changes
echo -e "${YELLOW}► Restarting services...${NC}"
docker compose restart messenger
sleep 3
echo -e "${GREEN}  ✓ Services restarted${NC}"

# 6. Cleanup
rm -rf "$TEMP_DIR"
echo -e "${GREEN}  ✓ Temp files cleaned${NC}"

# Done
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Restore completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Note: Users may need to re-login due to token invalidation.${NC}"
