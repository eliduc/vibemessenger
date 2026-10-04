import uuid
"""
User model and related schemas.
"""
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, ForeignKey, func
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field, field_validator
import re

from app.database import Base, TimestampMixin


# ============== Password Validation ==============

def validate_password_strength(password: str) -> tuple[bool, str | None]:
    """
    Validate password strength.
    
    Returns (is_valid, error_message).
    If valid, error_message is None.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    return True, None


class User(Base, TimestampMixin):
    """User database model."""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), unique=True, nullable=False, index=True)
    phone_hash = Column(String(64), unique=True, nullable=True, index=True)
    password_hash = Column(String(128), nullable=False)
    avatar_url = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    device_id = Column(String(64), nullable=True)
    push_token = Column(String(256), nullable=True)
    
    # Two-Factor Authentication (TOTP)
    totp_secret = Column(String(64), nullable=True)  # Encrypted TOTP secret
    totp_enabled = Column(Boolean, default=False)
    recovery_codes = Column(Text, nullable=True)  # JSON array of hashed codes
    
    # Permissions
    can_send_text = Column(Boolean, default=True)
    can_send_files = Column(Boolean, default=True)
    can_send_voice = Column(Boolean, default=True)
    can_call = Column(Boolean, default=True)
    is_blocked = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    
    key_bundles = relationship("KeyBundle", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class KeyBundle(Base, TimestampMixin):
    """User's public key bundle for X3DH key exchange."""
    __tablename__ = "key_bundles"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    identity_key = Column(String(64), nullable=False)
    signed_prekey_id = Column(Integer, nullable=False)
    signed_prekey = Column(String(64), nullable=False)
    signed_prekey_signature = Column(String(128), nullable=False)
    one_time_prekeys = Column(Text, default="[]")
    
    user = relationship("User", back_populates="key_bundles")


class RefreshToken(Base, TimestampMixin):
    """Refresh token for maintaining sessions."""
    __tablename__ = "refresh_tokens"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    device_id = Column(String(64), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="refresh_tokens")


# ============== Pydantic Schemas ==============

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    display_name: str = Field(..., min_length=2, max_length=100)
    device_id: str | None = Field(None, max_length=64)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores and hyphens')
        return v.lower()
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        is_valid, error_msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


class UserLogin(BaseModel):
    username: str
    password: str
    device_id: str | None = None
    totp_code: str | None = None  # 6-digit TOTP code or recovery code


class UserResponse(BaseModel):
    id: str
    username: str
    display_name: str
    avatar_url: str | None = None
    is_verified: bool
    is_admin: bool = False
    last_seen: datetime | None
    created_at: datetime
    
    class Config:
        from_attributes = True


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    refresh_token: str


class KeyBundleCreate(BaseModel):
    identity_key: str
    signed_prekey_id: int
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekeys: list[dict] = Field(default_factory=list)


class KeyBundleResponse(BaseModel):
    user_id: str
    identity_key: str
    signed_prekey_id: int
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekey: dict | None = None
    
    class Config:
        from_attributes = True


class PushSubscription(Base):
    """Push notification subscription storage."""
    __tablename__ = "push_subscriptions"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    endpoint = Column(String(500), nullable=False)
    p256dh = Column(String(200), nullable=False)
    auth = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ============== TOTP Schemas ==============

class TOTPSetupResponse(BaseModel):
    """Response for TOTP setup - contains secret and QR code."""
    secret: str
    qr_code: str  # Base64 encoded PNG
    provisioning_uri: str


class TOTPEnableRequest(BaseModel):
    """Request to enable TOTP after verification."""
    code: str = Field(..., min_length=6, max_length=6)


class TOTPEnableResponse(BaseModel):
    """Response after enabling TOTP - contains recovery codes."""
    enabled: bool
    recovery_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    """Request to verify TOTP code."""
    code: str = Field(..., min_length=6, max_length=10)  # 6 for TOTP, 9 for recovery (XXXX-XXXX)


class TOTPDisableRequest(BaseModel):
    """Request to disable TOTP."""
    password: str
    code: str = Field(..., min_length=6, max_length=10)


class TOTPStatusResponse(BaseModel):
    """TOTP status for current user."""
    enabled: bool
    has_recovery_codes: bool

