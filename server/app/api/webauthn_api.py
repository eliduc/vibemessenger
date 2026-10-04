# VibeMessenger - self-hosted end-to-end encrypted messenger.
# Copyright (C) 2026 eliduc
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
WebAuthn API endpoints for biometric/passkey authentication.
Version: 3.10.0

Supports:
- Passkey registration (attach biometric to existing account)
- Passkey login (authenticate without password)
- Step-up verification (biometric confirmation for sensitive actions)
- Credential management (list, rename, delete)

Works with Windows Hello, Face ID, Touch ID, and Android biometrics.
"""
import json
import logging
import os
import time
import secrets
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from urllib.parse import urlparse
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

import webauthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from app.database import get_db
from app.models.user import User, WebAuthnCredential
from app.services.auth_service import auth_service
from app.services.audit_service import audit_service as audit
from app.models.audit import AuditEventType, AuditSeverity
from app.api.auth import get_current_user_id, get_current_user
from app.config import settings
from app.rate_limiter import limiter, RATE_LIMIT_LOGIN

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webauthn", tags=["WebAuthn"])

# ============== Configuration ==============

# RP Name shown in browser biometric prompts
WEBAUTHN_RP_NAME = os.environ.get("MESSENGER_WEBAUTHN_RP_NAME", "VibeMessenger")

# RP ID — MUST be set in production (domain name, e.g. "stage.vibemessenger.ai")
WEBAUTHN_RP_ID = os.environ.get("MESSENGER_WEBAUTHN_RP_ID", "")

# Expected origin — MUST be set in production (e.g. "https://stage.vibemessenger.ai")
WEBAUTHN_EXPECTED_ORIGIN = os.environ.get("MESSENGER_WEBAUTHN_EXPECTED_ORIGIN", "")

# Challenge TTL in seconds
CHALLENGE_TTL = 300  # 5 minutes

# Step-up verification token TTL in seconds
VERIFY_TOKEN_TTL = 120  # 2 minutes


# ============== Challenge Store ==============

class ChallengeStore:
    """
    Thread-safe in-memory challenge store with TTL.
    
    Challenges are ephemeral values used in WebAuthn registration/authentication.
    They must be generated server-side and validated exactly once.
    """
    
    def __init__(self, ttl: int = CHALLENGE_TTL):
        self._store: dict[str, tuple[bytes, float, dict]] = {}  # key -> (challenge, expiry, metadata)
        self._lock = Lock()
        self._ttl = ttl
    
    def store(self, key: str, challenge: bytes, metadata: dict | None = None) -> None:
        """Store a challenge with TTL."""
        with self._lock:
            self._cleanup()
            self._store[key] = (challenge, time.time() + self._ttl, metadata or {})
    
    def retrieve(self, key: str) -> tuple[bytes, dict] | None:
        """Retrieve and consume a challenge (one-time use)."""
        with self._lock:
            self._cleanup()
            entry = self._store.pop(key, None)
            if entry is None:
                return None
            challenge, expiry, metadata = entry
            if time.time() > expiry:
                return None
            return challenge, metadata
    
    def _cleanup(self) -> None:
        """Remove expired entries."""
        now = time.time()
        expired = [k for k, (_, exp, _) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]


# Separate stores for different flows
_registration_challenges = ChallengeStore()
_authentication_challenges = ChallengeStore()
_verification_challenges = ChallengeStore()

# Step-up verification tokens (one-time use).
# ⚠️ КАО#220 (Round-3): this is a PER-PROCESS in-memory store. It is correct only under a SINGLE
# worker (a token minted on worker X won't validate on worker Y → spurious 403s). Stage/prod run one
# uvicorn worker (no --workers / replicas). Before any horizontal scaling, move this to a shared
# store (Redis/DB) keyed by token.
_verification_tokens: dict[str, tuple[str, float]] = {}  # token -> (user_id, expiry)
_verify_lock = Lock()


def consume_verify_token(token: str, expected_user_id: str) -> bool:
    """
    v3.11.8: Validate and consume a one-time step-up verification token.
    Returns True if token is valid for the given user. Token is consumed on success.
    """
    with _verify_lock:
        now = time.time()
        # Clean expired
        expired_keys = [k for k, (_, exp) in _verification_tokens.items() if now > exp]
        for k in expired_keys:
            del _verification_tokens[k]
        
        entry = _verification_tokens.pop(token, None)
        if entry is None:
            return False
        user_id, expiry = entry
        if now > expiry:
            return False
        if user_id != expected_user_id:
            return False
        return True


def issue_verify_token(user_id: str) -> tuple[str, int]:
    """
    КАО#220 (SER#22): Mint a one-time step-up verification token for a user.
    Reused by the passkey assertion path AND the password-fallback path so that
    password re-auth can also satisfy require_step_up_if_passkeys (otherwise a
    passkey user who falls back to password is permanently locked out of step-up
    actions). Returns (token, ttl_seconds).
    """
    token = secrets.token_urlsafe(32)
    with _verify_lock:
        now = time.time()
        expired_keys = [k for k, (_, exp) in _verification_tokens.items() if now > exp]
        for k in expired_keys:
            del _verification_tokens[k]
        _verification_tokens[token] = (user_id, now + VERIFY_TOKEN_TTL)
    return token, VERIFY_TOKEN_TTL


async def require_step_up_if_passkeys(
    request: Request, user_id: str, db: AsyncSession
) -> None:
    """
    v3.11.9: Enforce step-up verification for users who have registered passkeys.
    
    - If user has no WebAuthn credentials → allow (no step-up possible).
    - If user has credentials AND valid X-Verify-Token → allow (consume token).
    - If user has credentials but NO/invalid token → reject with 403.
    
    Raises HTTPException(403) if step-up is required but not provided.
    """
    # Check if user has any registered passkeys
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        ).limit(1)
    )
    has_passkeys = result.scalar_one_or_none() is not None
    
    if not has_passkeys:
        # No passkeys registered — can't require step-up, allow through
        return
    
    # User has passkeys — step-up is mandatory
    verify_token = request.headers.get("X-Verify-Token")
    if not verify_token:
        raise HTTPException(
            status_code=403,
            detail="Step-up verification required. Please verify with your passkey first."
        )
    
    if not consume_verify_token(verify_token, user_id):
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired verification token"
        )


# ============== Helpers ==============

def _get_rp_id(request: Request) -> str:
    """Get RP ID from configuration. Fails if not configured (v3.11.9: no request header fallback)."""
    if WEBAUTHN_RP_ID:
        return WEBAUTHN_RP_ID
    
    # v3.11.9: Fail-closed — do not guess from request headers
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="WebAuthn not configured: MESSENGER_WEBAUTHN_RP_ID environment variable is required"
    )


def _get_expected_origin(request: Request) -> str:
    """Get expected origin from configuration. Fails if not configured (v3.11.9: no request header fallback)."""
    if WEBAUTHN_EXPECTED_ORIGIN:
        return WEBAUTHN_EXPECTED_ORIGIN
    
    # v3.11.9: Fail-closed — do not guess from request headers
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="WebAuthn not configured: MESSENGER_WEBAUTHN_EXPECTED_ORIGIN environment variable is required"
    )


# ============== Pydantic Schemas ==============

class RegisterOptionsRequest(BaseModel):
    """Request body for registration options (optional device_name)."""
    device_name: str = Field(default="Passkey", max_length=100)


class RegisterVerifyRequest(BaseModel):
    """Attestation response from navigator.credentials.create()."""
    credential: dict
    device_name: str = Field(default="Passkey", max_length=100)


class AuthenticateOptionsRequest(BaseModel):
    """Request body for authentication options."""
    username: str = Field(default="", max_length=50)


class AuthenticateVerifyRequest(BaseModel):
    """Assertion response from navigator.credentials.get()."""
    credential: dict
    totp_code: str | None = None  # КАО#180 (C2): TOTP / recovery code for 2FA-enabled accounts


class VerifyCompleteRequest(BaseModel):
    """Assertion response for step-up verification."""
    credential: dict


class CredentialRenameRequest(BaseModel):
    """Request to rename a credential."""
    device_name: str = Field(..., min_length=1, max_length=100)


class CredentialResponse(BaseModel):
    """Response with credential info."""
    id: str
    device_name: str
    created_at: datetime
    last_used_at: datetime | None
    credential_device_type: str | None
    credential_backed_up: bool
    
    class Config:
        from_attributes = True


# ============== Registration Endpoints ==============

@router.post("/register/options")
async def register_options(
    request: Request,
    body: RegisterOptionsRequest = RegisterOptionsRequest(),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Generate WebAuthn registration options.
    
    Requires authentication (user must be logged in to register a passkey).
    Returns PublicKeyCredentialCreationOptions for navigator.credentials.create().
    """
    # Get user
    user = await auth_service.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get existing credentials to exclude (prevent duplicate registration)
    result = await db.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)
    )
    existing_creds = result.scalars().all()
    
    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(cred.credential_id),
        )
        for cred in existing_creds
    ]
    
    rp_id = _get_rp_id(request)
    
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=WEBAUTHN_RP_NAME,
        user_name=user.username,
        user_id=user.id.encode("utf-8"),
        user_display_name=user.display_name or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude_credentials if exclude_credentials else None,
        timeout=60000,
    )
    
    # Store challenge for verification (keyed by user_id)
    _registration_challenges.store(
        user_id,
        options.challenge,
        {"rp_id": rp_id, "device_name": body.device_name},
    )
    
    options_json = options_to_json(options)
    logger.info(f"[WebAuthn] Registration options generated for user {user.username} (rp_id={rp_id})")
    
    return json.loads(options_json)


@router.post("/register/verify")
async def register_verify(
    request: Request,
    body: RegisterVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Verify WebAuthn registration response.
    
    Validates the attestation from navigator.credentials.create() and
    stores the new credential in the database.
    """
    # Retrieve stored challenge
    stored = _registration_challenges.retrieve(user_id)
    if not stored:
        raise HTTPException(
            status_code=400,
            detail="Registration challenge expired or not found. Please try again.",
        )
    
    challenge, metadata = stored
    rp_id = metadata["rp_id"]
    expected_origin = _get_expected_origin(request)
    
    try:
        verification = verify_registration_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            require_user_verification=True,
        )
    except Exception as e:
        logger.warning(f"[WebAuthn] Registration verification failed for user {user_id}: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Registration verification failed: {str(e)}",
        )
    
    # Store credential in database
    credential_id_b64 = bytes_to_base64url(verification.credential_id)
    public_key_b64 = bytes_to_base64url(verification.credential_public_key)
    
    # Check if credential already exists
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id_b64
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Credential already registered")
    
    # Extract transports from credential response if available
    transports_json = None
    if isinstance(body.credential, dict):
        transports = body.credential.get("response", {}).get("transports")
        if not transports:
            transports = body.credential.get("transports")
        if transports and isinstance(transports, list):
            transports_json = json.dumps(transports)
    
    new_credential = WebAuthnCredential(
        user_id=user_id,
        credential_id=credential_id_b64,
        public_key=public_key_b64,
        sign_count=verification.sign_count,
        device_name=body.device_name,
        aaguid=verification.aaguid,
        credential_device_type=str(verification.credential_device_type.value)
            if verification.credential_device_type else None,
        credential_backed_up=verification.credential_backed_up,
        transports=transports_json,
    )
    db.add(new_credential)
    
    # Audit log
    await audit.log_event(
        db=db,
        event_type=AuditEventType.WEBAUTHN_REGISTERED,
        severity=AuditSeverity.INFO,
        user_id=user_id,
        request=request,
        details={"device_name": body.device_name, "credential_device_type": new_credential.credential_device_type},
    )
    await db.commit()
    
    logger.info(f"[WebAuthn] Credential registered for user {user_id}: {body.device_name}")
    
    return {
        "status": "ok",
        "credential_id": new_credential.id,
        "device_name": body.device_name,
    }


# ============== Authentication Endpoints ==============

@router.post("/authenticate/options")
@limiter.limit(RATE_LIMIT_LOGIN)
async def authenticate_options(
    request: Request,
    body: AuthenticateOptionsRequest = AuthenticateOptionsRequest(),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate WebAuthn authentication options.
    
    Public endpoint (no auth required — this is for login).
    If username is provided, returns options with that user's credentials.
    If empty, returns discoverable credential options (passkey autofill).
    """
    rp_id = _get_rp_id(request)
    allow_credentials = None
    
    # Generate a unique session key for this authentication attempt
    session_key = secrets.token_urlsafe(32)
    
    if body.username:
        # Find user and their credentials
        username = body.username.strip().lower()
        result = await db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        
        if user:
            result = await db.execute(
                select(WebAuthnCredential).where(
                    WebAuthnCredential.user_id == user.id
                )
            )
            creds = result.scalars().all()
            
            if creds:
                allow_credentials = []
                for cred in creds:
                    transports = None
                    if cred.transports:
                        try:
                            transports = json.loads(cred.transports)
                        except (json.JSONDecodeError, TypeError):
                            pass
                    
                    descriptor = PublicKeyCredentialDescriptor(
                        id=base64url_to_bytes(cred.credential_id),
                    )
                    allow_credentials.append(descriptor)
        
        # Don't reveal whether user exists — always return options
        # If no credentials found, return empty allowCredentials (browser may still offer discoverable creds)
    
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    
    # Store challenge keyed by session_key
    _authentication_challenges.store(
        session_key,
        options.challenge,
        {"rp_id": rp_id, "username": body.username},
    )
    
    options_json = json.loads(options_to_json(options))
    # Include session_key so client can reference it in verify request
    options_json["_session_key"] = session_key
    
    return options_json


@router.post("/authenticate/verify")
@limiter.limit(RATE_LIMIT_LOGIN)
async def authenticate_verify(
    request: Request,
    body: AuthenticateVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify WebAuthn authentication response and issue JWT tokens.
    
    Public endpoint (no auth required — this is the login flow).
    Returns the same token structure as password login.
    """
    # Extract session_key from credential (we embedded it in the options response)
    session_key = body.credential.get("_session_key", "")
    
    # Clean _session_key from credential before verification
    credential_data = {k: v for k, v in body.credential.items() if k != "_session_key"}
    
    if not session_key:
        raise HTTPException(status_code=400, detail="Missing session key")
    
    # Retrieve stored challenge
    stored = _authentication_challenges.retrieve(session_key)
    if not stored:
        raise HTTPException(
            status_code=400,
            detail="Authentication challenge expired or not found. Please try again.",
        )
    
    challenge, metadata = stored
    rp_id = metadata["rp_id"]
    expected_origin = _get_expected_origin(request)
    
    # Find the credential in our database
    raw_id = credential_data.get("rawId", credential_data.get("id", ""))
    
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == raw_id
        )
    )
    db_credential = result.scalar_one_or_none()
    
    if not db_credential:
        logger.warning(f"[WebAuthn] Authentication failed: credential not found (id prefix: {raw_id[:20]}...)")
        await audit.log_event(
            db=db,
            event_type=AuditEventType.WEBAUTHN_LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            request=request,
            details={"reason": "credential_not_found"},
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credential")
    
    # Get the user
    result = await db.execute(
        select(User).where(User.id == db_credential.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    
    if user.is_blocked:
        raise HTTPException(status_code=403, detail="Account is blocked")
    
    # Verify the authentication response
    try:
        verification = verify_authentication_response(
            credential=credential_data,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            credential_public_key=base64url_to_bytes(db_credential.public_key),
            credential_current_sign_count=db_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        logger.warning(f"[WebAuthn] Authentication verification failed for user {user.username}: {e}")
        await audit.log_event(
            db=db,
            event_type=AuditEventType.WEBAUTHN_LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            user_id=user.id,
            username=user.username,
            request=request,
            details={"reason": str(e)},
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Authentication verification failed")
    
    # Update sign count and last_used
    db_credential.sign_count = verification.new_sign_count
    db_credential.last_used_at = datetime.now(timezone.utc)
    
    # Update user last_seen
    user.last_seen = datetime.now(timezone.utc)

    # КАО#180 (C2): enforce TOTP 2FA for passkey login too (previously bypassed; password login enforces it).
    # Passkey is verified first (above); only then require the second factor for 2FA-enabled accounts.
    if user.totp_enabled:
        if not body.totp_code:
            raise HTTPException(status_code=403, detail="TOTP code required", headers={"X-TOTP-Required": "true"})
        from app.api.totp import verify_totp_code, consume_recovery_code
        totp_ok, is_recovery = await verify_totp_code(db, user, body.totp_code)
        if not totp_ok:
            raise HTTPException(status_code=401, detail="Invalid TOTP code")
        if is_recovery:
            # КАО#374: same as the password login — a failed consume means the code was already burned by a
            # concurrent request, so it must not authenticate here either.
            if not await consume_recovery_code(db, user, body.totp_code):
                raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # Create JWT token pair (same as password login)
    tokens = await auth_service._create_token_pair(db, user, None, request)
    
    # Audit log
    await audit.log_event(
        db=db,
        event_type=AuditEventType.WEBAUTHN_LOGIN,
        severity=AuditSeverity.INFO,
        user_id=user.id,
        username=user.username,
        request=request,
        details={"device_name": db_credential.device_name},
    )
    await db.commit()
    
    logger.info(f"[WebAuthn] User {user.username} authenticated via passkey: {db_credential.device_name}")
    
    from app.models.user import UserResponse
    return {
        "user": UserResponse.model_validate(user),
        "tokens": tokens,
        "auth_method": "webauthn",
    }


# ============== Step-Up Verification Endpoints ==============

@router.post("/verify/options")
async def verify_options(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Generate WebAuthn options for step-up verification.
    
    Requires authentication. Used to protect sensitive actions like:
    - Reset E2EE keys
    - Change password
    - Export account backup
    - Transfer group ownership
    - Disable 2FA
    """
    rp_id = _get_rp_id(request)
    
    # Get user's credentials
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        )
    )
    creds = result.scalars().all()
    
    if not creds:
        raise HTTPException(
            status_code=404,
            detail="No passkeys registered. Use password verification instead.",
        )
    
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(cred.credential_id),
        )
        for cred in creds
    ]
    
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    
    _verification_challenges.store(
        user_id,
        options.challenge,
        {"rp_id": rp_id},
    )
    
    return json.loads(options_to_json(options))


@router.post("/verify/complete")
async def verify_complete(
    request: Request,
    body: VerifyCompleteRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Verify step-up authentication and return a short-lived verification token.
    
    The token can be included in subsequent requests to protected endpoints.
    """
    stored = _verification_challenges.retrieve(user_id)
    if not stored:
        raise HTTPException(
            status_code=400,
            detail="Verification challenge expired. Please try again.",
        )
    
    challenge, metadata = stored
    rp_id = metadata["rp_id"]
    expected_origin = _get_expected_origin(request)
    
    # Find the credential
    raw_id = body.credential.get("rawId", body.credential.get("id", ""))
    
    result = await db.execute(
        select(WebAuthnCredential).where(
            and_(
                WebAuthnCredential.credential_id == raw_id,
                WebAuthnCredential.user_id == user_id,
            )
        )
    )
    db_credential = result.scalar_one_or_none()
    
    if not db_credential:
        raise HTTPException(status_code=401, detail="Invalid credential")
    
    try:
        verification = verify_authentication_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            credential_public_key=base64url_to_bytes(db_credential.public_key),
            credential_current_sign_count=db_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        logger.warning(f"[WebAuthn] Step-up verification failed for user {user_id}: {e}")
        raise HTTPException(status_code=401, detail="Verification failed")
    
    # Update sign count and last_used
    db_credential.sign_count = verification.new_sign_count
    db_credential.last_used_at = datetime.now(timezone.utc)
    
    # Generate a one-time verification token (КАО#220: shared helper)
    verify_token, _ = issue_verify_token(user_id)

    # Audit log
    await audit.log_event(
        db=db,
        event_type=AuditEventType.WEBAUTHN_VERIFY,
        severity=AuditSeverity.INFO,
        user_id=user_id,
        request=request,
        details={"device_name": db_credential.device_name},
    )
    await db.commit()
    
    return {
        "status": "verified",
        "verify_token": verify_token,
        "expires_in": VERIFY_TOKEN_TTL,
    }


# ============== Credential Management Endpoints ==============

@router.get("/credentials", response_model=list[CredentialResponse])
async def list_credentials(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """List all registered WebAuthn credentials for the current user."""
    result = await db.execute(
        select(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user_id)
        .order_by(WebAuthnCredential.created_at.desc())
    )
    creds = result.scalars().all()
    
    return [
        CredentialResponse(
            id=cred.id,
            device_name=cred.device_name,
            created_at=cred.created_at,
            last_used_at=cred.last_used_at,
            credential_device_type=cred.credential_device_type,
            credential_backed_up=cred.credential_backed_up,
        )
        for cred in creds
    ]


@router.put("/credentials/{credential_id}")
async def rename_credential(
    credential_id: str,
    body: CredentialRenameRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Rename a WebAuthn credential."""
    result = await db.execute(
        select(WebAuthnCredential).where(
            and_(
                WebAuthnCredential.id == credential_id,
                WebAuthnCredential.user_id == user_id,
            )
        )
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    cred.device_name = body.device_name
    await db.commit()
    
    return {"status": "ok", "device_name": body.device_name}


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Delete a WebAuthn credential."""
    result = await db.execute(
        select(WebAuthnCredential).where(
            and_(
                WebAuthnCredential.id == credential_id,
                WebAuthnCredential.user_id == user_id,
            )
        )
    )
    cred = result.scalar_one_or_none()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    device_name = cred.device_name
    await db.delete(cred)
    
    await audit.log_event(
        db=db,
        event_type=AuditEventType.WEBAUTHN_REMOVED,
        severity=AuditSeverity.INFO,
        user_id=user_id,
        request=request,
        details={"device_name": device_name, "credential_id": credential_id},
    )
    await db.commit()
    
    logger.info(f"[WebAuthn] Credential deleted for user {user_id}: {device_name}")
    
    return {"status": "ok", "message": f"Passkey '{device_name}' removed"}


# ============== Status Endpoint ==============

@router.get("/status")
async def webauthn_status(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get WebAuthn status for the current user."""
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        )
    )
    creds = result.scalars().all()
    
    return {
        "enabled": len(creds) > 0,
        "credential_count": len(creds),
        "credentials": [
            {
                "id": c.id,
                "device_name": c.device_name,
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in creds
        ],
    }


# ============== Check Endpoint (Public) ==============

@router.get("/check/{username}")
async def check_webauthn_available(
    username: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Check if a user has WebAuthn credentials registered.
    
    Public endpoint used by login screen to show biometric login button.
    Returns minimal info to avoid user enumeration.
    """
    result = await db.execute(
        select(User).where(User.username == username.lower())
    )
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal user doesn't exist
        return {"available": False}
    
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id
        )
    )
    creds = result.scalars().all()
    
    return {"available": len(creds) > 0}
