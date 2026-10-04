#!/bin/bash
# VibeMessenger Backup Cleanup Script
# Keeps: 7 daily + 4 weekly backups
# Usage: ./backup-cleanup.sh [backup_dir]

BACKUP_DIR="${1:-/mnt/backup}"
DAILY_KEEP=7
WEEKLY_KEEP=4

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Cleaning up old backups in $BACKUP_DIR${NC}"

# Get all backup files sorted by date (oldest first)
BACKUPS=($(ls -t "$BACKUP_DIR"/vibemessenger-backup-*.tar.gz 2>/dev/null))
TOTAL=${#BACKUPS[@]}

if [ $TOTAL -eq 0 ]; then
    echo "No backups found."
    exit 0
fi

echo "Found $TOTAL backup(s)"

# Keep the most recent DAILY_KEEP backups
KEEP_COUNT=$((DAILY_KEEP + WEEKLY_KEEP))

if [ $TOTAL -le $KEEP_COUNT ]; then
    echo "Only $TOTAL backups exist, keeping all (threshold: $KEEP_COUNT)"
    exit 0
fi

# Calculate how many to delete
DELETE_COUNT=$((TOTAL - KEEP_COUNT))

echo -e "${YELLOW}Deleting $DELETE_COUNT old backup(s)...${NC}"

# Delete oldest backups (they're at the end of the sorted array)
for ((i = KEEP_COUNT; i < TOTAL; i++)); do
    BACKUP="${BACKUPS[$i]}"
    SIZE=$(du -h "$BACKUP" | cut -f1)
    echo "  Deleting: $(basename "$BACKUP") ($SIZE)"
    rm -f "$BACKUP"
done

echo -e "${GREEN}Cleanup complete.${NC}"

# Show remaining backups
echo ""
echo "Remaining backups:"
ls -lht "$BACKUP_DIR"/vibemessenger-backup-*.tar.gz 2>/dev/null | head -10

# Show disk usage
DISK_FREE=$(df -h "$BACKUP_DIR" | tail -1 | awk '{print $4}')
echo ""
echo -e "${YELLOW}Disk space remaining: ${DISK_FREE}${NC}"
