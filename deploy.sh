#!/bin/bash
#
# Secure Messenger - Deployment Script for Raspberry Pi
# 
# Usage: ./deploy.sh [command]
# Commands:
#   install   - First-time installation
#   update    - Update to latest version
#   start     - Start all services
#   stop      - Stop all services
#   restart   - Restart all services
#   status    - Show service status
#   logs      - Show logs
#   backup    - Backup database
#   ssl       - Setup SSL with Let's Encrypt

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${PROJECT_DIR}/data"
BACKUP_DIR="${PROJECT_DIR}/backups"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_requirements() {
    log_info "Checking requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        echo "Install with: curl -fsSL https://get.docker.com | sh"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    log_info "All requirements met"
}

generate_secrets() {
    if [ ! -f "${PROJECT_DIR}/.env" ]; then
        log_info "Generating secrets..."
        
        cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
        
        # Generate secure random values
        SECRET_KEY=$(openssl rand -hex 32)
        DB_PASSWORD=$(openssl rand -hex 16)
        TURN_SECRET=$(openssl rand -hex 16)
        
        # Update .env file
        sed -i "s/your_secure_database_password_here/${DB_PASSWORD}/" "${PROJECT_DIR}/.env"
        sed -i "s/your_32_byte_hex_secret_key_here/${SECRET_KEY}/" "${PROJECT_DIR}/.env"
        sed -i "s/your_turn_server_secret_here/${TURN_SECRET}/" "${PROJECT_DIR}/.env"
        
        # Update TURN config
        sed -i "s/YOUR_TURN_SECRET_HERE/${TURN_SECRET}/" "${PROJECT_DIR}/config/turnserver.conf"
        
        log_info "Secrets generated. Edit .env to customize settings."
    else
        log_warn ".env already exists, skipping secret generation"
    fi
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p "${DATA_DIR}/uploads"
    mkdir -p "${DATA_DIR}/certbot"
    mkdir -p "${BACKUP_DIR}"
    mkdir -p "${PROJECT_DIR}/config/ssl"
}

install() {
    log_info "Starting installation..."
    
    check_requirements
    create_directories
    generate_secrets
    
    # Build and start
    log_info "Building Docker images..."
    docker compose build
    
    log_info "Starting services..."
    docker compose up -d
    
    # Wait for services
    log_info "Waiting for services to start..."
    sleep 10
    
    # Check health
    if curl -s http://localhost:8443/health > /dev/null; then
        log_info "Installation complete!"
        echo ""
        echo "Server is running at: http://$(hostname -I | awk '{print $1}'):8000"
        echo ""
        echo "Next steps:"
        echo "1. Configure your domain in .env"
        echo "2. Run './deploy.sh ssl' to enable HTTPS"
        echo "3. Configure Flutter client with your server IP"
    else
        log_error "Server health check failed"
        docker compose logs messenger
        exit 1
    fi
}

update() {
    log_info "Updating..."
    
    # Pull latest code (if using git)
    if [ -d .git ]; then
        git pull
    fi
    
    # Rebuild and restart
    docker compose build
    docker compose up -d
    
    log_info "Update complete"
}

start() {
    log_info "Starting services..."
    docker compose up -d
    log_info "Services started"
}

stop() {
    log_info "Stopping services..."
    docker compose down
    log_info "Services stopped"
}

restart() {
    log_info "Restarting services..."
    docker compose restart
    log_info "Services restarted"
}

status() {
    echo "=== Service Status ==="
    docker compose ps
    echo ""
    echo "=== Health Check ==="
    curl -s http://localhost:8443/health | python3 -m json.tool 2>/dev/null || echo "Server not responding"
    echo ""
    echo "=== Resource Usage ==="
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null || true
}

logs() {
    SERVICE=${2:-""}
    if [ -n "$SERVICE" ]; then
        docker compose logs -f "$SERVICE"
    else
        docker compose logs -f
    fi
}

backup() {
    log_info "Creating backup..."
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="${BACKUP_DIR}/backup_${TIMESTAMP}.sql"
    
    # Backup PostgreSQL
    docker compose exec -T postgres pg_dump -U messenger messenger > "$BACKUP_FILE"
    
    # Compress
    gzip "$BACKUP_FILE"
    
    log_info "Backup created: ${BACKUP_FILE}.gz"
    
    # Clean old backups (keep last 7)
    ls -t "${BACKUP_DIR}"/backup_*.sql.gz 2>/dev/null | tail -n +8 | xargs -r rm
}

setup_ssl() {
    log_info "Setting up SSL..."
    
    # Check if domain is configured
    DOMAIN=$(grep "^TURN_REALM=" .env | cut -d= -f2)
    if [ "$DOMAIN" = "your.domain.com" ] || [ -z "$DOMAIN" ]; then
        log_error "Please configure your domain in .env first"
        exit 1
    fi
    
    # Install certbot if not present
    if ! command -v certbot &> /dev/null; then
        log_info "Installing certbot..."
        sudo apt-get update
        sudo apt-get install -y certbot
    fi
    
    # Stop nginx temporarily
    docker compose stop nginx 2>/dev/null || true
    
    # Get certificate
    log_info "Obtaining SSL certificate for $DOMAIN..."
    sudo certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email "admin@${DOMAIN}"
    
    # Copy certificates
    sudo cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${PROJECT_DIR}/config/ssl/"
    sudo cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${PROJECT_DIR}/config/ssl/"
    sudo chown -R $USER:$USER "${PROJECT_DIR}/config/ssl/"
    
    # Create nginx config with SSL
    cat > "${PROJECT_DIR}/config/nginx.conf" << EOF
events {
    worker_connections 1024;
}

http {
    upstream messenger {
        server messenger:8000;
    }

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name ${DOMAIN};
        return 301 https://\$server_name\$request_uri;
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name ${DOMAIN};

        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        # API
        location /api/ {
            proxy_pass http://messenger;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # WebSocket
        location /ws {
            proxy_pass http://messenger;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_read_timeout 86400;
        }

        # Health check
        location /health {
            proxy_pass http://messenger;
        }

        location / {
            proxy_pass http://messenger;
        }
    }
}
EOF

    # Restart services
    docker compose up -d
    
    log_info "SSL setup complete!"
    echo "Your server is now available at: https://${DOMAIN}"
    
    # Setup auto-renewal
    log_info "Setting up certificate auto-renewal..."
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'cp /etc/letsencrypt/live/${DOMAIN}/*.pem ${PROJECT_DIR}/config/ssl/ && docker compose restart nginx'") | crontab -
}

show_help() {
    echo "Secure Messenger Deployment Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install   First-time installation"
    echo "  update    Update to latest version"
    echo "  start     Start all services"
    echo "  stop      Stop all services"
    echo "  restart   Restart all services"
    echo "  status    Show service status"
    echo "  logs      Show logs (optionally: logs [service])"
    echo "  backup    Backup database"
    echo "  ssl       Setup SSL with Let's Encrypt"
    echo ""
}

# Main
case "${1:-help}" in
    install)
        install
        ;;
    update)
        update
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs "$@"
        ;;
    backup)
        backup
        ;;
    ssl)
        setup_ssl
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
