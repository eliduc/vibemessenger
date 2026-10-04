#!/bin/bash
# VibeMessenger Backup Script
# Usage: ./backup.sh [backup_dir]

set -e

# Configuration
BACKUP_DIR="${1:-/mnt/backup}"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
BACKUP_NAME="vibemessenger-backup-${TIMESTAMP}"
TEMP_DIR="/tmp/${BACKUP_NAME}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   VibeMessenger Backup - ${TIMESTAMP}${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"

# Check backup directory
if [ ! -d "$BACKUP_DIR" ]; then
    echo -e "${RED}Error: Backup directory $BACKUP_DIR does not exist${NC}"
    exit 1
fi

if [ ! -w "$BACKUP_DIR" ]; then
    echo -e "${RED}Error: Backup directory $BACKUP_DIR is not writable${NC}"
    exit 1
fi

# Check if docker is running
if ! docker ps &> /dev/null; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Create temp directory
mkdir -p "$TEMP_DIR"
echo -e "${YELLOW}► Created temp directory: $TEMP_DIR${NC}"

# 1. Backup PostgreSQL database
echo -e "${YELLOW}► Backing up PostgreSQL database...${NC}"
cd "$PROJECT_DIR"

# Get database credentials from .env
if [ -f .env ]; then
    source .env
fi
DB_USER="${POSTGRES_USER:-messenger}"
DB_NAME="${POSTGRES_DB:-messenger}"

docker compose exec -T postgres pg_dump -U "$DB_USER" "$DB_NAME" > "$TEMP_DIR/database.sql"
DB_SIZE=$(du -h "$TEMP_DIR/database.sql" | cut -f1)
echo -e "${GREEN}  ✓ Database backup: $DB_SIZE${NC}"

# 2. Backup avatars (user avatars)
echo -e "${YELLOW}► Backing up user avatars...${NC}"
if docker compose exec -T messenger test -d /app/data/avatars 2>/dev/null; then
    docker compose cp messenger:/app/data/avatars "$TEMP_DIR/avatars" 2>/dev/null || mkdir -p "$TEMP_DIR/avatars"
    AVATAR_COUNT=$(find "$TEMP_DIR/avatars" -type f 2>/dev/null | wc -l)
    echo -e "${GREEN}  ✓ User avatars: $AVATAR_COUNT files${NC}"
else
    mkdir -p "$TEMP_DIR/avatars"
    echo -e "${GREEN}  ✓ User avatars: 0 files (directory empty)${NC}"
fi

# 3. Backup group avatars
echo -e "${YELLOW}► Backing up group avatars...${NC}"
if docker compose exec -T messenger test -d /app/data/group_avatars 2>/dev/null; then
    docker compose cp messenger:/app/data/group_avatars "$TEMP_DIR/group_avatars" 2>/dev/null || mkdir -p "$TEMP_DIR/group_avatars"
    GROUP_AVATAR_COUNT=$(find "$TEMP_DIR/group_avatars" -type f 2>/dev/null | wc -l)
    echo -e "${GREEN}  ✓ Group avatars: $GROUP_AVATAR_COUNT files${NC}"
else
    mkdir -p "$TEMP_DIR/group_avatars"
    echo -e "${GREEN}  ✓ Group avatars: 0 files (directory empty)${NC}"
fi

# 4. Backup uploaded files
echo -e "${YELLOW}► Backing up uploaded files...${NC}"
if docker compose exec -T messenger test -d /app/data/uploads 2>/dev/null; then
    docker compose cp messenger:/app/data/uploads "$TEMP_DIR/uploads" 2>/dev/null || mkdir -p "$TEMP_DIR/uploads"
    UPLOAD_COUNT=$(find "$TEMP_DIR/uploads" -type f 2>/dev/null | wc -l)
    UPLOAD_SIZE=$(du -sh "$TEMP_DIR/uploads" 2>/dev/null | cut -f1)
    echo -e "${GREEN}  ✓ Uploaded files: $UPLOAD_COUNT files ($UPLOAD_SIZE)${NC}"
else
    mkdir -p "$TEMP_DIR/uploads"
    echo -e "${GREEN}  ✓ Uploaded files: 0 files (directory empty)${NC}"
fi

# 5. Create metadata
echo -e "${YELLOW}► Creating metadata...${NC}"
cat > "$TEMP_DIR/metadata.json" << EOF
{
    "backup_version": "1.0",
    "created_at": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "project_dir": "$PROJECT_DIR",
    "database": {
        "user": "$DB_USER",
        "name": "$DB_NAME",
        "size": "$DB_SIZE"
    },
    "stats": {
        "user_avatars": $AVATAR_COUNT,
        "group_avatars": $GROUP_AVATAR_COUNT,
        "uploaded_files": $UPLOAD_COUNT
    }
}
EOF
echo -e "${GREEN}  ✓ Metadata created${NC}"

# 6. Create archive
echo -e "${YELLOW}► Creating archive...${NC}"
ARCHIVE_PATH="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
tar -czf "$ARCHIVE_PATH" -C /tmp "$BACKUP_NAME"
ARCHIVE_SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
echo -e "${GREEN}  ✓ Archive created: $ARCHIVE_SIZE${NC}"

# 7. Cleanup
rm -rf "$TEMP_DIR"
echo -e "${GREEN}  ✓ Temp files cleaned${NC}"

# 8. Show result
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Backup completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "   File: ${ARCHIVE_PATH}"
echo -e "   Size: ${ARCHIVE_SIZE}"
echo ""

# 9. List recent backups
echo -e "${YELLOW}Recent backups in ${BACKUP_DIR}:${NC}"
ls -lht "$BACKUP_DIR"/vibemessenger-backup-*.tar.gz 2>/dev/null | head -5

# 10. Show disk usage
echo ""
DISK_FREE=$(df -h "$BACKUP_DIR" | tail -1 | awk '{print $4}')
echo -e "${YELLOW}Disk space remaining: ${DISK_FREE}${NC}"
