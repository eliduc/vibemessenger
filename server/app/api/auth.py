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
Authentication API endpoints.
Version: 3.7.3 - Session revocation check on every request
"""
import os
import re
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select, and_
from app.database import get_db
from app.models.user import (
    User, UserCreate, UserLogin, UserResponse, 
    TokenPair, TokenRefresh, RefreshToken,
    SessionInfo, SessionsListResponse
)
from app.services.auth_service import auth_service
from app.config import settings
from app.rate_limiter import limiter, user_limiter, RATE_LIMIT_LOGIN, RATE_LIMIT_REGISTER  # KAO#350: per-user limit for account deletion
from app.services.audit_service import audit_service as audit
from app.models.audit import AuditEventType, AuditSeverity
from datetime import datetime, timezone, timedelta

AVATAR_DIR = "/app/data/avatars"
os.makedirs(AVATAR_DIR, exist_ok=True)

# Regex pattern for valid avatar filenames: UUID_hex.extension
# Example: 550e8400-e29b-41d4-a716-446655440000_a1b2c3d4.jpg
AVATAR_FILENAME_PATTERN = re.compile(
    r'^[a-f0-9\-]{36}_[a-f0-9]{8}\.(jpg|jpeg|png|gif|webp)$',
    re.IGNORECASE
)

import logging
logger = logging.getLogger(__name__)  # KAO#352: there was NO module-level logger, so every
# `logger.warning(...)` written in a module-scope function raised NameError instead of logging.

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


def validate_avatar_filename(filename: str, base_dir: str) -> str:
    """
    Validate avatar filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to validate
        base_dir: The base directory for avatars
        
    Returns:
        Safe absolute filepath
        
    Raises:
        HTTPException: If filename is invalid or attempts path traversal
    """
    # Check for path traversal attempts
    if not filename or '..' in filename or '/' in filename or '\\' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Extract only the basename (extra safety)
    safe_filename = os.path.basename(filename)
    
    # Validate filename format
    if not AVATAR_FILENAME_PATTERN.match(safe_filename):
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    # Build and resolve the path
    base_path = Path(base_dir).resolve()
    file_path = (base_path / safe_filename).resolve()
    
    # Ensure the resolved path is within base directory
    try:
        file_path.relative_to(base_path)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    return str(file_path)


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> str:
    """
    Extract and validate user ID from JWT token.
    
    v3.7.3: Also validates that the session is not revoked.
    """
    payload = auth_service.decode_access_token(credentials.credentials)
    
    # v3.7.3: Check if session is revoked by verifying access_token_jti
    jti = payload.get("jti")
    if jti:
        result = await db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.access_token_jti == jti,
                    RefreshToken.is_revoked == False,
                )
            )
        )
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked"
            )

    # КАО#009 (SER#23/SER#30): reject blocked/deactivated users immediately on the access-token path
    sub_id = payload["sub"]
    user_row = await db.execute(select(User).where(User.id == sub_id))
    user_obj = user_row.scalar_one_or_none()
    if not user_obj or not user_obj.is_active or user_obj.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is not active"
        )

    return sub_id


async def get_current_token_jti(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Extract JTI (token ID) from JWT token for session identification."""
    payload = auth_service.decode_access_token(credentials.credentials)
    return payload.get("jti", "")


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get current authenticated user."""
    user = await auth_service.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user


@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_REGISTER)
async def register(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user.
    
    Returns user info and authentication tokens.
    Rate limited: 3 requests per minute per IP.
    """
    user, tokens = await auth_service.register_user(db, user_data, request)
    
    # Log user registration
    await audit.log_event(
        db=db,
        event_type=AuditEventType.USER_REGISTERED,
        severity=AuditSeverity.INFO,
        user_id=user.id,
        username=user.username,
        request=request,
    )
    await db.commit()
    
    return {
        "user": UserResponse.model_validate(user),
        "tokens": tokens,
    }


@router.post("/login", response_model=dict)
@limiter.limit(RATE_LIMIT_LOGIN)
async def login(
    request: Request,
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user with username and password.
    
    If 2FA is enabled, totp_code is required.
    Returns user info and authentication tokens.
    Rate limited: 5 requests per minute per IP.
    """
    from app.api.totp import verify_totp_code, consume_recovery_code
    
    try:
        user, tokens = await auth_service.login_user(
            db,
            credentials.username,
            credentials.password,
            credentials.device_id,
            request,
            skip_totp=True,       # We handle TOTP here
            create_tokens=False,  # КАО#248 (#18): mint the session only after TOTP passes (below)
        )
    except HTTPException as e:
        # Log failed login attempt
        await audit.log_login_failed(
            db=db,
            username=credentials.username,
            request=request,
            reason=e.detail,
        )
        await db.commit()
        raise
    
    # Check if TOTP is enabled
    if user.totp_enabled:
        if not credentials.totp_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="TOTP code required",
                headers={"X-TOTP-Required": "true"},
            )
        
        # Verify TOTP or recovery code
        is_valid, is_recovery = await verify_totp_code(db, user, credentials.totp_code)
        
        # v3.11.9: Auto-rewrap legacy plaintext TOTP secrets on successful login
        if is_valid and user.totp_secret and not user.totp_secret.startswith("enc:"):
            try:
                from app.api.totp import _auto_rewrap_totp_secret
                await _auto_rewrap_totp_secret(db, user)
            except Exception:
                pass  # Don't fail login if rewrap fails
        
        if not is_valid:
            # Log failed TOTP attempt
            await audit.log_event(
                db=db,
                event_type=AuditEventType.TOTP_FAILED,
                severity=AuditSeverity.WARNING,
                user_id=user.id,
                username=user.username,
                request=request,
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid TOTP code"
            )
        
        # If recovery code was used, consume it and log
        if is_recovery:
            # КАО#374: consumption is AUTHORITATIVE. verify_totp_code() only CHECKS the code against the
            # list it read earlier and never consumes, so discarding this result meant two logins racing on
            # the same recovery code both succeeded: whoever lost the consume race still got tokens. Treat a
            # failed consume as an invalid code — it means somebody else burned it first.
            if not await consume_recovery_code(db, user, credentials.totp_code):
                # Same shape as the TOTP_FAILED branch above: log_login_failed() does NOT take user_id,
                # so calling it here would raise TypeError on a real login path.
                await audit.log_event(
                    db=db,
                    event_type=AuditEventType.TOTP_FAILED,
                    severity=AuditSeverity.WARNING,
                    user_id=user.id,
                    username=user.username,
                    request=request,
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid TOTP code"
                )
            await audit.log_event(
                db=db,
                event_type=AuditEventType.RECOVERY_CODE_USED,
                severity=AuditSeverity.WARNING,
                user_id=user.id,
                username=user.username,
                request=request,
            )
    
    # КАО#248 (#18): all factors passed — NOW mint the session (no token was created on the
    # password/2FA-failure paths above, so a failed 2FA can no longer leave a usable session behind).
    tokens = await auth_service.issue_tokens(db, user, credentials.device_id, request)

    # Log successful login
    await audit.log_login_success(
        db=db,
        user_id=user.id,
        username=user.username,
        request=request,
        details={"device_id": credentials.device_id} if credentials.device_id else None,
    )
    await db.commit()

    return {
        "user": UserResponse.model_validate(user),
        "tokens": tokens,
        "totp_enabled": user.totp_enabled or False,
    }


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(
    request: Request,
    data: TokenRefresh,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh access token using refresh token.
    
    The old refresh token is invalidated (rotation).
    v3.7.0: Updates session activity tracking.
    """
    tokens = await auth_service.refresh_tokens(db, data.refresh_token, request)
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    refresh_token: TokenRefresh | None = None,
    all_devices: bool = False,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Logout user.
    
    - With refresh_token: revokes that specific token
    - With all_devices=True: revokes all refresh tokens
    """
    await auth_service.logout(
        db,
        user_id,
        refresh_token.refresh_token if refresh_token else None,
        all_devices,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(
    user = Depends(get_current_user),
):
    """Get current user info."""
    return UserResponse.model_validate(user)



@router.put("/me", response_model=UserResponse)
async def update_me(
    display_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    user = Depends(get_current_user),
):
    """Update current user info."""
    if display_name:
        user.display_name = display_name
        await db.commit()
    
    return UserResponse.model_validate(user)


@router.get("/user/{display_name}")
async def get_user_by_display_name(
    display_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get user by display name OR username (КАО#305)."""
    # КАО#305: this only matched display_name, but the sole caller is the "New Chat" dialog whose input
    # literally says "Enter username" (index.html #new-chat-username) — so anyone typing the username of
    # a user whose display name differs got "User not found" and simply could not start a chat with them.
    # It stayed hidden because most accounts have display_name == username. Match the username FIRST
    # (it is unique) and fall back to display_name, preserving the previous behaviour.
    identifier = display_name
    # KAO#350: never surface a deleted (deactivated) account - you must not be able to start a NEW chat
    # with one. Existing history still renders, because the tombstone row is still readable by id.
    result = await db.execute(
        select(User).where(and_(User.username == identifier, User.is_active == True))
    )
    user = result.scalar_one_or_none()
    if not user:
        result = await db.execute(
            select(User).where(and_(User.display_name == identifier, User.is_active == True))
        )
        user = result.scalars().first()  # display_name is not guaranteed unique

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
    }


@router.get("/user/id/{user_id}")
async def get_user_by_id(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get user by ID."""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
    }


class VerifyPasswordRequest(BaseModel):
    password: str


@router.post("/verify-password")
@limiter.limit("10/minute")  # КАО#220 (Round-3): tighter than login (30/min) — this endpoint now mints step-up tokens, so its limit is the brute-force ceiling for the password step-up path
async def verify_password(
    request: Request,
    body: VerifyPasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify current user's password without side effects.
    Used as fallback when biometric verification is unavailable.
    v3.10.0: Added for biometric auth password fallback."""
    verified = auth_service.verify_password(body.password, current_user.password_hash)
    if not verified:
        await audit.log_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            user_id=current_user.id,
            username=current_user.username,
            request=request,
            details={"reason": "Password verification failed (biometric fallback)"}
        )
        return {"verified": False}
    # КАО#220 (SER#22): issue a step-up verify token so the password fallback can satisfy
    # require_step_up_if_passkeys — otherwise a passkey user who falls back to password is
    # permanently locked out of step-up-gated actions (e.g. transfer ownership).
    from app.api.webauthn_api import issue_verify_token
    token, ttl = issue_verify_token(current_user.id)
    return {"verified": True, "verify_token": token, "expires_in": ttl}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
async def change_password(
    http_request: Request,
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    current_jti: str = Depends(get_current_token_jti),
    db: AsyncSession = Depends(get_db),
):
    """Change user password."""
    from app.models.user import validate_password_strength
    
    if not auth_service.verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password strength (same rules as registration)
    is_valid, error_msg = validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    current_user.password_hash = auth_service.hash_password(request.new_password)

    # КАО#008 (SER#25): revoke all OTHER sessions on password change (keep current)
    other_tokens = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.user_id == current_user.id,
                RefreshToken.is_revoked == False,
                RefreshToken.access_token_jti != current_jti,
            )
        )
    )
    for _t in other_tokens.scalars().all():
        _t.is_revoked = True

    # Log password change
    await audit.log_password_change(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        request=http_request,
    )
    await db.commit()
    
    return {"message": "Password changed successfully"}



@router.get("/me/permissions")
async def get_my_permissions(
    current_user: User = Depends(get_current_user),
):
    """Get current user's permissions."""
    return {
        "can_send_text": current_user.can_send_text,
        "can_send_files": current_user.can_send_files,
        "can_send_voice": current_user.can_send_voice,
        "can_call": current_user.can_call,
        "is_blocked": current_user.is_blocked,
        "is_admin": current_user.is_admin,
    }


@router.get("/user/{user_id}/online")
async def check_user_online(
    user_id: str,
    current_user: User = Depends(get_current_user),
):
    """Check if a user is online."""
    from app.services.websocket_manager import ws_manager
    import logging
    logger = logging.getLogger(__name__)
    is_online = ws_manager.is_online(user_id)
    logger.info(f"Online check for {user_id}: {is_online}, connections: {list(ws_manager._connections.keys())}")
    return {"user_id": user_id, "online": is_online}


@router.get("/users/online")
async def get_online_users(
    current_user: User = Depends(get_current_user),
):
    """Get list of all online user IDs."""
    from app.services.websocket_manager import ws_manager
    online_users = ws_manager.get_online_users()
    # Don't include current user in the list
    online_users = [uid for uid in online_users if uid != current_user.id]
    return {"online_users": online_users}


# Allowed image types for avatars
ALLOWED_AVATAR_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
ALLOWED_AVATAR_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload user avatar."""
    import aiofiles
    
    # Validate file type - strict whitelist
    if not file.content_type or file.content_type not in ALLOWED_AVATAR_TYPES:
        raise HTTPException(status_code=400, detail="File must be an image (JPEG, PNG, GIF, or WebP)")
    
    # Validate and sanitize extension
    ext = 'jpg'  # default
    if file.filename and "." in file.filename:
        ext = file.filename.rsplit(".", 1)[-1].lower()
        if ext not in ALLOWED_AVATAR_EXTENSIONS:
            ext = 'jpg'
    
    # Generate safe unique filename
    filename = f"{current_user.id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(AVATAR_DIR, filename)
    
    # Max avatar size from config
    max_size = settings.max_avatar_size
    total_size = 0
    chunk_size = 256 * 1024  # 256KB chunks
    
    # Read and write in chunks with size check
    try:
        async with aiofiles.open(filepath, 'wb') as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                
                total_size += len(chunk)
                if total_size > max_size:
                    await f.close()
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    raise HTTPException(
                        status_code=400, 
                        detail=f"File too large (max {max_size // 1024 // 1024}MB)"
                    )
                
                await f.write(chunk)
    except HTTPException:
        raise
    except Exception:
        if os.path.exists(filepath):
            os.remove(filepath)
        raise HTTPException(status_code=500, detail="Failed to save avatar")
    
    # Delete old avatar if exists
    if current_user.avatar_url:
        old_filename = current_user.avatar_url.split("/")[-1]
        old_filepath = os.path.join(AVATAR_DIR, old_filename)
        # Extra safety: only delete if within AVATAR_DIR
        try:
            old_path = Path(old_filepath).resolve()
            base_path = Path(AVATAR_DIR).resolve()
            if old_path.is_relative_to(base_path) and old_path.exists():
                os.remove(old_path)
        except (ValueError, OSError):
            pass  # Ignore errors when deleting old avatar
    
    # Update user
    avatar_url = f"/api/v1/auth/avatar/{filename}"
    current_user.avatar_url = avatar_url
    await db.commit()
    
    return {"avatar_url": avatar_url}


@router.get("/avatar/{filename}")
async def get_avatar(filename: str):
    """Get avatar image with path traversal protection."""
    from fastapi.responses import FileResponse
    
    # Validate filename and get safe filepath
    filepath = validate_avatar_filename(filename, AVATAR_DIR)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    return FileResponse(filepath)


@router.delete("/avatar")
async def delete_avatar(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete user avatar."""
    if current_user.avatar_url:
        filename = current_user.avatar_url.split("/")[-1]
        # Use safe path validation
        try:
            filepath = validate_avatar_filename(filename, AVATAR_DIR)
            if os.path.exists(filepath):
                os.remove(filepath)
        except HTTPException:
            pass  # Ignore invalid filename errors during delete
        
        current_user.avatar_url = None
        await db.commit()
    return {"message": "Avatar deleted"}


# ==============================================================================
# SESSION MANAGEMENT (v3.7.0)
# ==============================================================================

def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (from nginx/proxy)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


def parse_user_agent(user_agent: str | None) -> str:
    """Parse and simplify user agent string."""
    if not user_agent:
        return "Unknown"
    
    # Truncate if too long
    if len(user_agent) > 512:
        user_agent = user_agent[:509] + "..."
    
    return user_agent


@router.get("/sessions", response_model=SessionsListResponse)
async def get_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Get list of active sessions for current user.
    
    v3.7.0: New endpoint for session management UI.
    v3.7.1: Auto-revoke sessions inactive for more than 48 hours.
    v3.7.2: Use access_token_jti for reliable current session identification.
    """
    # v3.7.2: Get jti from current access token to identify current session
    current_token = credentials.credentials
    try:
        payload = auth_service.decode_access_token(current_token)
        current_jti = payload.get("jti")
    except Exception:
        current_jti = None
    
    # v3.7.1: Threshold for auto-revoking inactive sessions
    inactivity_threshold = datetime.now(timezone.utc) - timedelta(hours=48)
    
    # Query all active (non-revoked, non-expired) refresh tokens
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        ).order_by(RefreshToken.last_activity.desc().nullslast())
    )
    tokens = result.scalars().all()
    
    sessions = []
    revoked_count = 0
    
    for token in tokens:
        # v3.7.1: Auto-revoke sessions inactive for more than 48 hours
        if token.last_activity and token.last_activity < inactivity_threshold:
            token.is_revoked = True
            revoked_count += 1
            continue  # Don't include in response
        
        # v3.7.2: Reliably identify current session by jti
        is_current = (current_jti is not None and token.access_token_jti == current_jti)
        
        session_info = SessionInfo(
            id=token.id,
            device_id=token.device_id,
            ip_address=token.ip_address,
            user_agent=token.user_agent,
            last_activity=token.last_activity,
            created_at=token.created_at,
            is_current=is_current
        )
        sessions.append(session_info)
    
    # Commit revoked sessions if any
    if revoked_count > 0:
        await db.commit()
    
    # v3.7.2: Fallback to IP+UA heuristic only if jti match not found
    # This handles old sessions created before v3.7.2
    if sessions and not any(s.is_current for s in sessions):
        current_ip = get_client_ip(request)
        current_ua = request.headers.get("user-agent", "")
        
        for session in sessions:
            if session.ip_address == current_ip and session.user_agent == current_ua:
                session.is_current = True
                break
        
        # If still no match, mark the most recent as current
        if not any(s.is_current for s in sessions):
            sessions[0].is_current = True
    
    return SessionsListResponse(
        sessions=sessions,
        total=len(sessions)
    )


@router.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Terminate a specific session.
    
    v3.7.0: New endpoint for session management.
    """
    # Find the session
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.id == session_id,
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            )
        )
    )
    token = result.scalar_one_or_none()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Revoke the token
    token.is_revoked = True
    await db.commit()
    
    return {"message": "Session terminated", "session_id": session_id}


@router.delete("/sessions")
async def terminate_other_sessions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Terminate all sessions except the current one.
    
    v3.7.0: New endpoint for "logout everywhere else".
    v3.7.2: Use access_token_jti for reliable current session identification.
    """
    # v3.7.2: Get jti from current access token to identify current session
    current_token = credentials.credentials
    try:
        payload = auth_service.decode_access_token(current_token)
        current_jti = payload.get("jti")
    except Exception:
        current_jti = None
    
    # Fallback values for old sessions without jti
    current_ip = get_client_ip(request)
    current_ua = request.headers.get("user-agent", "")
    
    # Get all active sessions
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        ).order_by(RefreshToken.last_activity.desc().nullslast())
    )
    tokens = result.scalars().all()
    
    revoked_count = 0
    kept_session_id = None
    
    # Find and keep the current session, revoke others
    for token in tokens:
        # v3.7.2: Primary method - match by jti
        is_current = (current_jti is not None and token.access_token_jti == current_jti)
        
        # Fallback for old sessions: IP + User-Agent heuristic
        if not is_current and current_jti is None:
            is_current = (token.ip_address == current_ip and token.user_agent == current_ua)
        
        if is_current and kept_session_id is None:
            kept_session_id = token.id
            continue
        
        token.is_revoked = True
        revoked_count += 1
    
    # If no session was identified as current, keep the most recent one
    if kept_session_id is None and tokens:
        # Restore the first one (most recent)
        tokens[0].is_revoked = False
        revoked_count -= 1
        kept_session_id = tokens[0].id
    
    await db.commit()
    
    return {
        "message": f"Terminated {revoked_count} other sessions",
        "revoked_count": revoked_count,
        "kept_session_id": kept_session_id
    }


class DeleteAccountRequest(BaseModel):
    """KAO#350: self-service account deletion."""
    password: str
    totp_code: str | None = None


@router.delete("/me", status_code=status.HTTP_200_OK)
# KAO#350: limit PER USER, not per IP - this endpoint is authenticated, and an IP limit would let one
# person behind a shared NAT block everyone else from deleting their own account.
@user_limiter.limit("5/hour")
async def delete_my_account(
    request: Request,
    body: DeleteAccountRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    KAO#350: permanently delete the caller's own account.

    Model: DESTROY THE IDENTITY, KEEP OTHER PEOPLE'S CONVERSATIONS.

    In an end-to-end encrypted messenger the messages this user already SENT physically live on the
    recipients' devices; the server cannot recall them, and pretending otherwise would be dishonest. So
    everything that identifies or authenticates the user is destroyed irreversibly, while messages that
    were already delivered stay put, with the sender rendered as a deleted account.

    Destroyed for good: key bundles (nobody can ever open a NEW session with them), every refresh token
    and live socket, the TOTP secret and recovery codes, passkeys, push subscriptions, uploaded files and
    the avatar, and any message of theirs that was never delivered.

    Anonymised rather than removed: the user row itself. Ten tables (messages, group_members, poll_votes,
    pinned_messages, reactions, ...) reference users WITHOUT a foreign key, so dropping the row would
    leave dangling ids and the other party's history would start rendering "Unknown". The row therefore
    survives as a tombstone: random credentials, is_active = False, renamed to deleted_<id>.
    (A plain DELETE does NOT fail, which is worse: key_bundles/refresh_tokens cascade via the ORM
    relationship and push_subscriptions/file_metadata are ON DELETE CASCADE, so it succeeds and leaves
    the ten FK-less tables dangling. Verified on production - see КАО#378.)
    """
    import os
    import secrets as _secrets
    from sqlalchemy import delete as sa_delete, or_ as sa_or, update as sa_update
    from sqlalchemy.exc import IntegrityError
    from app.models.user import KeyBundle, RefreshToken, PushSubscription, WebAuthnCredential
    from app.models.message import (
        Message, MessageStatus, MessageReaction, MessageUserDeletion, PinnedMessage, SavedMessage,
    )
    from app.models.group import Group, GroupMember, ROLE_HIERARCHY
    from app.models.file import FileMetadata
    from app.models.poll import FavoriteMessage, PollVote
    from app.api.user_settings import MutedChat, UserBlock
    # KAO#353: ws_manager was NEVER imported here. The "kick every live socket" step therefore raised
    # NameError on every call, which the bare `except Exception: pass` swallowed - the endpoint returned
    # 200 while the deleted account kept a fully working socket (typing, calls, delivery).
    from app.services.websocket_manager import ws_manager

    user_id = current_user.id

    # ---- 1. prove it is really them -------------------------------------------------------------
    if not auth_service.verify_password(body.password, current_user.password_hash):
        await audit.log_event(
            db=db, event_type=AuditEventType.LOGIN_FAILED, severity=AuditSeverity.WARNING,
            user_id=user_id, request=request, details="account deletion refused: wrong password",
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    if current_user.totp_enabled:
        from app.api.totp import verify_totp_code
        if not body.totp_code:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="TOTP code required")
        ok, _is_recovery = await verify_totp_code(db, current_user, body.totp_code)
        if not ok:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    # КАО#378: the deletion itself now lives in app/services/account_deletion.py, so the admin route
    # uses THE SAME code path. It used to be a bare `db.delete(user)`, which does not fail (the FK-backed
    # tables cascade) and therefore silently corrupted on every call - measured on production: 124
    # messages and 19 groups left pointing at users that no longer existed.
    # Phases 1b..7 moved verbatim; only the actor/target attribution in the audit row changed.
    from app.services.account_deletion import purge_user_account, AccountDeletionError, AlreadyDeleted

    try:
        result = await purge_user_account(
            db, user_id,
            actor_id=user_id,
            actor_username=current_user.username,
            request=request,
            reason="account deleted by its owner",
        )
    except AlreadyDeleted:
        # Idempotent: the caller is looking at an account that is already gone.
        return {"status": "deleted", "pending_messages_removed": 0,
                "groups_transferred": 0, "groups_deleted": 0, "files_removed": 0}
    except AccountDeletionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )

    return {
        "status": "deleted",
        "pending_messages_removed": result["pending_messages_removed"],
        "groups_transferred": result["groups_transferred"],
        "groups_deleted": result["groups_deleted"],
        "files_removed": result["files_removed"],
    }
