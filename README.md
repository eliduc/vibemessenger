# VibeMessenger

Self-hosted secure messaging application for small teams (200-300 users), optimized for Raspberry Pi deployment.

## ⚠️ Security Status

**Version:** 3.11.65  
**Date:** 2026-10-04

| Area | Status | Notes |
|------|--------|-------|
| JWT Authentication | ✅ Secure | 30 min access tokens, refresh rotation |
| WebSocket Auth | ✅ Secure | Token via Sec-WebSocket-Protocol (not URL) |
| SECRET_KEY | ✅ Validated | Fail-fast on insecure keys |
| XSS Protection | ✅ Hardened | escapeHtml + escapeJsString for all user data |
| File Uploads | ✅ Protected | Streaming size check, 20MB limit |
| CORS | ✅ Configurable | No wildcard by default |
| Private Keys | ⚠️ Generate locally | Never included in distribution archive |

**Note:** This is a self-hosted solution. Always review security for your specific deployment.

## Repository contents

This repository holds the **application source only**. Everything that carries key material is excluded by
`.gitignore` and must be generated per deployment:

| Not in the repo | How to produce it |
|---|---|
| `.env` | copy `.env.example` and fill it in — `SECRET_KEY` and `DB_PASSWORD` with `openssl rand -hex 32` |
| `certs/` | your own TLS certificate and key |
| `vapid_*.pem` | `./generate-keys.sh` |

The app refuses to start with an insecure `SECRET_KEY`, so a deployment cannot accidentally run on the
example values.

## 🔐 Security Features

- **JWT Authentication** — Short-lived access tokens (30 min) with refresh rotation
- **WebSocket Security** — Token via subprotocol header (not in URL/logs)
- **XSS Protection** — All user input escaped for HTML and JS contexts
- **File Access Control** — Only message participants can access files
- **Streaming Uploads** — Size checked during upload to prevent DoS
- **Key Validation** — Application refuses to start with insecure SECRET_KEY

## 📱 Features

- 1:1 and Group Chats with invitations
- Voice/Video Calls (WebRTC with TURN support)
- File Sharing (images, documents, voice messages)
- Disappearing Messages (1 minute to 7 days)
- Message Actions (edit, delete, reply, forward, pin, search)
- Typing Indicators and Read Receipts
- Offline Mode with message queue
- PWA Support (installable on mobile)

## 🚀 Quick Start

### Requirements

- Raspberry Pi 4 (4GB+ RAM) or any Linux server
- Docker and Docker Compose
- Domain with SSL certificate (for production)

### Installation

```bash
# 1. Extract release archive
tar -xzf vibemessenger-release-v3.1.tar.gz
cd vibemessenger-release-v3.1

# 2. Generate SSL certificates and VAPID keys
./generate-keys.sh

# 3. Configure environment
cp .env.example .env
nano .env

# Required settings:
#   MESSENGER_SECRET_KEY=$(openssl rand -hex 32)
#   DB_PASSWORD=<random password>

# 4. Start services
docker compose up -d

# 5. Verify
curl -k https://localhost:7443/health
```

## 🔧 Configuration

See `.env.example` for all available options.

**Critical settings:**
- `MESSENGER_SECRET_KEY` — Must be 32+ characters, random (app won't start otherwise)
- `DB_PASSWORD` — Database password

## 🔄 Backup & Restore

```bash
./backup.sh /mnt/backup
./restore.sh /mnt/backup/vibemessenger-backup-TIMESTAMP.tar.gz
```

## 📁 Creating Distribution Archive

```bash
./create-release.sh v3.1
```

This creates an archive WITHOUT private keys (generate on target system).

## 📄 License

MIT License
