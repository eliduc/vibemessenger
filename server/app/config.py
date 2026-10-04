"""
Secure Messenger Server Configuration
"""
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from functools import lru_cache
from pathlib import Path
import sys


# Insecure default values that should never be used in production
INSECURE_SECRET_KEYS = {
    "",
    "CHANGE-THIS-IN-PRODUCTION-USE-STRONG-KEY",
    "change-this-in-production",
    "secret",
    "secret_key",
    "your-secret-key",
    "changeme",
    "password",
    "test",
    "dev",
}


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # App
    app_name: str = "Secure Messenger"
    app_version: str = "0.1.0"
    debug: bool = False
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/messenger.db",
        description="Database connection string"
    )
    
    # Security
    secret_key: str = Field(
        default="CHANGE-THIS-IN-PRODUCTION-USE-STRONG-KEY",
        description="Secret key for JWT signing"
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30
    
    # File storage
    upload_dir: Path = Path("./data/uploads")
    
    # File size limits (in bytes)
    # Note: nginx client_max_body_size should be >= max of these values
    max_file_size: int = 10 * 1024 * 1024  # 10MB for general files
    max_avatar_size: int = 5 * 1024 * 1024  # 5MB for avatars
    nginx_body_limit: int = 20 * 1024 * 1024  # 20MB nginx limit (buffer)
    
    # User storage quota
    user_storage_quota: int = 100 * 1024 * 1024  # 100MB per user
    
    # Unattached file TTL (hours)
    unattached_file_ttl_hours: int = 24
    
    # WebSocket
    ws_heartbeat_interval: int = 30
    ws_max_connections_per_user: int = 5
    
    # Rate limiting (requests per minute)
    rate_limit_enabled: bool = True
    rate_limit_login: str = "30/minute"      # Login attempts
    rate_limit_register: str = "30/minute"   # Registration attempts
    rate_limit_send: str = "60/minute"      # Message sending
    rate_limit_preview: str = "30/minute"   # Link preview requests
    rate_limit_upload: str = "10/minute"    # File uploads
    rate_limit_default: str = "100/minute"  # Default for other endpoints
    
    # Push notifications (optional)
    fcm_credentials_path: str | None = None
    apns_key_path: str | None = None

    # Push notifications
    vapid_public_key: str = ""
    vapid_private_key_file: str = "/app/vapid_private.pem"
    vapid_email: str = "mailto:admin@localhost"

    # WebRTC / TURN
    turn_enabled: bool = True
    turn_server_url: str = "global.relay.metered.ca"
    turn_server_port: int = 443
    turn_username: str = ""
    turn_credential: str = ""
    stun_server_url: str = "stun:stun.relay.metered.ca:80"
    
    # CORS
    cors_origins: str = ""  # Comma-separated list of allowed origins, empty = same origin only
    
    # v3.11.9: Envelope encryption key for TOTP secrets at rest
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    totp_encryption_key: str = ""
    
    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate SECRET_KEY is secure."""
        # Check if it's an insecure default value
        if v.lower() in {s.lower() for s in INSECURE_SECRET_KEYS}:
            print("\n" + "="*60, file=sys.stderr)
            print("FATAL ERROR: SECRET_KEY is insecure!", file=sys.stderr)
            print("="*60, file=sys.stderr)
            print(f"Current value: '{v[:10]}...' (truncated)", file=sys.stderr)
            print("", file=sys.stderr)
            print("You must set a strong SECRET_KEY in your .env file:", file=sys.stderr)
            print("  MESSENGER_SECRET_KEY=$(openssl rand -hex 32)", file=sys.stderr)
            print("="*60 + "\n", file=sys.stderr)
            sys.exit(1)
        
        # Check minimum length (32 characters = 256 bits for HS256)
        if len(v) < 32:
            print("\n" + "="*60, file=sys.stderr)
            print("FATAL ERROR: SECRET_KEY is too short!", file=sys.stderr)
            print("="*60, file=sys.stderr)
            print(f"Current length: {len(v)} characters", file=sys.stderr)
            print("Required: at least 32 characters", file=sys.stderr)
            print("", file=sys.stderr)
            print("Generate a secure key with:", file=sys.stderr)
            print("  openssl rand -hex 32", file=sys.stderr)
            print("="*60 + "\n", file=sys.stderr)
            sys.exit(1)
        
        return v
    
    class Config:
        env_file = ".env"
        env_prefix = "MESSENGER_"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
