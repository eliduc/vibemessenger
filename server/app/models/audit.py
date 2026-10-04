# VibeMessenger - self-hosted end-to-end encrypted messenger.
# Copyright (C) 2026 RLG
#
# This program is free software: you may redistribute it and/or modify it under
# the terms of the GNU Affero General Public License, version 3, as published by
# the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU AGPL v3 <https://www.gnu.org/licenses/agpl-3.0.html>;
# a verbatim copy ships in the LICENSE file at the root of this repository.
#
# AGPL section 13: if you modify this program and let users interact with it
# over a network, you must offer those users the complete corresponding source
# of your modified version, at no charge, from a network server.

"""
Audit Log model for security event tracking.
"""
from datetime import datetime
from uuid import uuid4
from enum import Enum

from sqlalchemy import Column, String, DateTime, Text, Index
from pydantic import BaseModel

from app.database import Base


class AuditEventType(str, Enum):
    """Types of audit events."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    
    # Password events
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    
    # 2FA events
    TOTP_ENABLED = "totp_enabled"
    TOTP_DISABLED = "totp_disabled"
    TOTP_FAILED = "totp_failed"
    RECOVERY_CODE_USED = "recovery_code_used"
    
    # User management
    USER_REGISTERED = "user_registered"
    USER_BLOCKED = "user_blocked"
    USER_UNBLOCKED = "user_unblocked"
    USER_DELETED = "user_deleted"
    PROFILE_UPDATED = "profile_updated"
    
    # Admin events
    ADMIN_GRANTED = "admin_granted"
    ADMIN_REVOKED = "admin_revoked"
    ADMIN_ACTION = "admin_action"
    USER_PERMISSIONS_CHANGED = "user_permissions_changed"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_TOKEN = "invalid_token"
    
    # WebAuthn events
    WEBAUTHN_REGISTERED = "webauthn_registered"
    WEBAUTHN_LOGIN = "webauthn_login"
    WEBAUTHN_LOGIN_FAILED = "webauthn_login_failed"
    WEBAUTHN_VERIFY = "webauthn_verify"
    WEBAUTHN_REMOVED = "webauthn_removed"
    
    # Group events
    GROUP_CREATED = "group_created"
    GROUP_DELETED = "group_deleted"
    GROUP_MEMBER_ADDED = "group_member_added"
    GROUP_MEMBER_REMOVED = "group_member_removed"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditLog(Base):
    """
    Audit log entry for security events.
    
    Stores all security-relevant actions for:
    - Compliance requirements
    - Security incident investigation
    - User activity monitoring
    """
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Event info
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default=AuditSeverity.INFO.value)
    
    # Actor
    user_id = Column(String(36), nullable=True, index=True)  # Who performed the action
    username = Column(String(100), nullable=True)  # Cached for historical reference
    
    # Target (optional - for actions on other users/resources)
    target_user_id = Column(String(36), nullable=True, index=True)
    target_resource_id = Column(String(36), nullable=True)
    target_resource_type = Column(String(50), nullable=True)  # 'user', 'group', 'message', etc.
    
    # Request info
    ip_address = Column(String(45), nullable=True, index=True)  # IPv4 or IPv6
    user_agent = Column(String(500), nullable=True)
    
    # Additional details (JSON)
    details = Column(Text, nullable=True)  # JSON string with event-specific data
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Indexes for efficient querying
    __table_args__ = (
        Index('ix_audit_user_event', 'user_id', 'event_type'),
        Index('ix_audit_time_event', 'created_at', 'event_type'),
    )


# ============== Pydantic Schemas ==============

class AuditLogCreate(BaseModel):
    """Schema for creating an audit log entry."""
    event_type: AuditEventType
    severity: AuditSeverity = AuditSeverity.INFO
    user_id: str | None = None
    username: str | None = None
    target_user_id: str | None = None
    target_resource_id: str | None = None
    target_resource_type: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict | None = None


class AuditLogResponse(BaseModel):
    """Schema for audit log response."""
    id: str
    event_type: str
    severity: str
    user_id: str | None
    username: str | None
    target_user_id: str | None
    target_resource_id: str | None
    target_resource_type: str | None
    ip_address: str | None
    user_agent: str | None
    details: str | None
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogQuery(BaseModel):
    """Query parameters for audit logs."""
    event_type: AuditEventType | None = None
    user_id: str | None = None
    target_user_id: str | None = None
    ip_address: str | None = None
    severity: AuditSeverity | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    limit: int = 100
    offset: int = 0
