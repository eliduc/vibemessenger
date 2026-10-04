"""
Two-Factor Authentication (TOTP) API endpoints.
v3.11.9: Added envelope encryption for TOTP secrets at rest.
"""
import io
import json
import os
import secrets
import hashlib
import base64
import time  # КАО#301: TOTP replay protection needs the current time step
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import or_, select, update as sa_update  # КАО#320/#338: atomic TOTP + recovery-code consumption
from sqlalchemy.ext.asyncio import AsyncSession

import pyotp
import qrcode

from app.database import get_db
from app.models.user import (
    User,
    TOTPSetupResponse,
    TOTPEnableRequest,
    TOTPEnableResponse,
    TOTPVerifyRequest,
    TOTPDisableRequest,
    TOTPStatusResponse,
)
from app.api.auth import get_current_user
from app.services.auth_service import auth_service
from app.services.audit_service import audit_service as audit
from app.config import settings
from app.rate_limiter import user_limiter  # КАО#242 (#1): throttle 2FA-management brute force

import logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/totp", tags=["Two-Factor Authentication"])

# App name for authenticator display
APP_NAME = "VibeMessenger"

# Recovery codes config
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LENGTH = 8  # 8 chars = XXXX-XXXX format


# ==============================================================================
# TOTP SECRET ENVELOPE ENCRYPTION (v3.11.9)
# ==============================================================================

def _get_totp_encryption_key() -> bytes | None:
    """Get the 32-byte encryption key for TOTP secrets, or None if not configured."""
    key_hex = settings.totp_encryption_key
    if not key_hex:
        return None
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            logger.error(f"[TOTP] Encryption key must be 32 bytes (64 hex chars), got {len(key)}")
            return None
        return key
    except ValueError:
        logger.error("[TOTP] Encryption key is not valid hex")
        return None


def _encrypt_totp_secret(plaintext_secret: str) -> str:
    """
    Encrypt a TOTP secret with AES-256-GCM using the master key.
    Returns: 'enc:' + base64(nonce[12] + ciphertext + tag[16])
    If no encryption key is configured, returns plaintext with a warning.
    """
    key = _get_totp_encryption_key()
    if key is None:
        logger.warning("[TOTP] No encryption key configured — storing TOTP secret in plaintext!")
        return plaintext_secret
    
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_secret.encode('utf-8'), None)
    combined = nonce + ciphertext
    return "enc:" + base64.b64encode(combined).decode('ascii')


def _decrypt_totp_secret(stored_value: str) -> str:
    """
    Decrypt a TOTP secret from DB. Handles both encrypted ('enc:...') and legacy plaintext.
    """
    if not stored_value:
        return stored_value
    
    if not stored_value.startswith("enc:"):
        # Legacy plaintext — return as-is
        return stored_value
    
    key = _get_totp_encryption_key()
    if key is None:
        raise ValueError("TOTP secret is encrypted but MESSENGER_TOTP_ENCRYPTION_KEY is not set")
    
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    combined = base64.b64decode(stored_value[4:])  # Skip 'enc:' prefix
    if len(combined) < 28:  # 12 nonce + minimum ciphertext
        raise ValueError(f"Encrypted TOTP blob too short: {len(combined)}")
    nonce = combined[:12]
    ciphertext = combined[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')


async def _consume_totp(db: AsyncSession, user: User, plaintext_secret: str, code: str, valid_window: int = 1) -> bool:
    """
    КАО#301: verify a TOTP code AND burn it, so it cannot be replayed.

    pyotp.verify() only answers "is this code currently valid", and a code stays valid for its whole
    30-second step plus the ±1 window — so the same code could previously be submitted several times
    (e.g. login, then again to disable 2FA) within ~90s. Here we identify WHICH time-step matched and
    refuse anything at or below the highest step already accepted for this user, then record it.

    The caller must commit; every call site does (login/webauthn commit for the audit log, the TOTP
    endpoints commit their own state change).
    """
    totp = pyotp.TOTP(plaintext_secret)
    step = getattr(totp, "interval", 30) or 30
    current = int(time.time()) // step
    matched = None
    for offset in range(-valid_window, valid_window + 1):
        counter = current + offset
        if totp.verify(code, for_time=counter * step, valid_window=0):
            matched = counter
            break
    if matched is None:
        return False

    # КАО#320: burn the step ATOMICALLY. The first version did read-modify-write on the ORM object
    # (`if counter <= user.totp_last_counter: reject` then assign), so two requests carrying the SAME code
    # could both read the old value and both succeed — the very replay КАО#301 set out to stop. A single
    # conditional UPDATE lets the database arbitrate: exactly one row update wins.
    result = await db.execute(
        sa_update(User)
        .where(
            User.id == user.id,
            or_(User.totp_last_counter.is_(None), User.totp_last_counter < matched),
        )
        .values(totp_last_counter=matched)
    )
    if result.rowcount == 0:
        return False  # another request already consumed this step (replay)
    user.totp_last_counter = matched  # keep the in-memory instance consistent
    return True


async def _auto_rewrap_totp_secret(db: AsyncSession, user: User) -> str:
    """
    If TOTP secret is legacy plaintext and encryption key is available,
    automatically re-encrypt and save. Returns the plaintext secret.
    """
    if not user.totp_secret:
        return ""
    
    if user.totp_secret.startswith("enc:"):
        # Already encrypted
        return _decrypt_totp_secret(user.totp_secret)
    
    # Legacy plaintext
    plaintext = user.totp_secret
    key = _get_totp_encryption_key()
    if key is not None:
        # Re-wrap
        user.totp_secret = _encrypt_totp_secret(plaintext)
        await db.commit()
        logger.info(f"[TOTP] Re-encrypted legacy TOTP secret for user {user.id}")
    
    return plaintext


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Generate random recovery codes in XXXX-XXXX format."""
    codes = []
    for _ in range(count):
        # Generate 8 random alphanumeric characters (uppercase + digits)
        chars = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(RECOVERY_CODE_LENGTH))
        # Format as XXXX-XXXX
        code = f"{chars[:4]}-{chars[4:]}"
        codes.append(code)
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for storage."""
    # Normalize: remove dashes, uppercase
    normalized = code.replace('-', '').upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


def verify_recovery_code(code: str, hashed_codes: list[str]) -> tuple[bool, int]:
    """
    Verify a recovery code against stored hashes.
    Returns (is_valid, index) where index is the position of the used code.
    """
    code_hash = hash_recovery_code(code)
    for i, stored_hash in enumerate(hashed_codes):
        if secrets.compare_digest(code_hash, stored_hash):
            return True, i
    return False, -1


def generate_qr_code(provisioning_uri: str) -> str:
    """Generate QR code as base64 PNG."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode('utf-8')


@router.get("/status", response_model=TOTPStatusResponse)
async def get_totp_status(
    current_user: User = Depends(get_current_user),
):
    """Get current TOTP status for the user."""
    recovery_codes = []
    if current_user.recovery_codes:
        try:
            recovery_codes = json.loads(current_user.recovery_codes)
        except json.JSONDecodeError:
            pass
    
    return TOTPStatusResponse(
        enabled=current_user.totp_enabled or False,
        has_recovery_codes=len(recovery_codes) > 0,
    )


@router.post("/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initialize TOTP setup.
    
    Returns a secret key and QR code for the user to scan with their
    authenticator app. The TOTP is NOT enabled yet - user must verify
    with /enable endpoint.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled. Disable it first to set up again."
        )
    
    # Generate new TOTP secret
    secret = pyotp.random_base32()
    
    # Store secret encrypted (not enabled yet)
    current_user.totp_secret = _encrypt_totp_secret(secret)
    await db.commit()
    
    # Generate provisioning URI for QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name=APP_NAME,
    )
    
    # Generate QR code
    qr_code = generate_qr_code(provisioning_uri)
    
    return TOTPSetupResponse(
        secret=secret,
        qr_code=qr_code,
        provisioning_uri=provisioning_uri,
    )


@router.post("/enable", response_model=TOTPEnableResponse)
async def enable_totp(
    http_request: Request,
    request: TOTPEnableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Enable TOTP after verifying the code.
    
    User must have called /setup first to get a secret.
    This endpoint verifies that the authenticator app is properly
    configured before enabling 2FA.
    
    Returns recovery codes that should be saved securely.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is already enabled"
        )
    
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP not set up. Call /setup first."
        )
    
    # Verify the code (decrypt secret first)
    plaintext_secret = _decrypt_totp_secret(current_user.totp_secret)
    if not await _consume_totp(db, current_user, plaintext_secret, request.code):  # КАО#301: single-use
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Make sure your authenticator app is synced."
        )
    
    # Generate recovery codes
    recovery_codes = generate_recovery_codes()
    hashed_codes = [hash_recovery_code(code) for code in recovery_codes]
    
    # Enable TOTP
    current_user.totp_enabled = True
    current_user.recovery_codes = json.dumps(hashed_codes)
    
    # Log TOTP enabled
    await audit.log_totp_enabled(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        request=http_request,
    )
    await db.commit()
    
    return TOTPEnableResponse(
        enabled=True,
        recovery_codes=recovery_codes,
    )


@router.post("/disable")
@user_limiter.limit("10/minute")  # КАО#242 (#1): cap TOTP/recovery-code guessing on 2FA disable
async def disable_totp(
    request: Request,            # КАО#242: slowapi requires the starlette Request param be named `request`
    body: TOTPDisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Disable TOTP.
    
    Requires password and a valid TOTP code (or recovery code) for security.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is not enabled"
        )
    
    # Verify password
    if not auth_service.verify_password(body.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    # Verify TOTP or recovery code
    is_valid = False

    # Try TOTP first (decrypt secret)
    if current_user.totp_secret:
        # КАО#337: КАО#319 guarded verify_totp_code but not this path — an undecryptable secret (e.g. after
        # rotating MESSENGER_TOTP_ENCRYPTION_KEY) raised here, 500'd, and the user could never turn 2FA
        # off: their recovery codes, checked just below and needing no secret, were unreachable.
        plaintext_secret = None
        try:
            plaintext_secret = _decrypt_totp_secret(current_user.totp_secret)
        except Exception as e:
            logger.error(f"[TOTP] disable: secret undecryptable for {current_user.id}: {e} — recovery codes only")
        if plaintext_secret and await _consume_totp(db, current_user, plaintext_secret, body.code):  # КАО#301/#337
            is_valid = True

    # Try recovery code
    if not is_valid and current_user.recovery_codes:
        try:
            hashed_codes = json.loads(current_user.recovery_codes)
            valid, _ = verify_recovery_code(body.code, hashed_codes)
            if valid:
                is_valid = True
        except json.JSONDecodeError:
            pass
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP or recovery code"
        )
    
    # Disable TOTP
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.recovery_codes = None
    
    # Log TOTP disabled
    await audit.log_totp_disabled(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        request=request,
    )
    await db.commit()
    
    return {"message": "Two-factor authentication disabled"}


@router.post("/regenerate-recovery-codes", response_model=TOTPEnableResponse)
@user_limiter.limit("10/minute")  # КАО#242 (#1): cap TOTP-code guessing on recovery-code regeneration
async def regenerate_recovery_codes(
    request: Request,            # КАО#242: slowapi requires the starlette Request param be named `request`
    body: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate new recovery codes.
    
    Requires a valid TOTP code. Old recovery codes are invalidated.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP is not enabled"
        )
    
    # Verify TOTP code (decrypt secret first)
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,  # КАО#242 Round-2: client-state error, not 500
            detail="TOTP secret not found"
        )
    
    # КАО#337: same guard — regenerating recovery codes must stay possible with a recovery code.
    plaintext_secret = None
    try:
        plaintext_secret = _decrypt_totp_secret(current_user.totp_secret)
    except Exception as e:
        logger.error(f"[TOTP] regenerate: secret undecryptable for {current_user.id}: {e}")
    # КАО#337: with no usable secret the TOTP branch cannot run; a recovery code is the only way in.
    _regen_ok = bool(plaintext_secret) and await _consume_totp(db, current_user, plaintext_secret, body.code)
    if not _regen_ok and current_user.recovery_codes:
        _regen_ok = await consume_recovery_code(db, current_user, body.code)
    if not _regen_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code"
        )

    # Generate new recovery codes
    recovery_codes = generate_recovery_codes()
    hashed_codes = [hash_recovery_code(code) for code in recovery_codes]
    
    current_user.recovery_codes = json.dumps(hashed_codes)
    await db.commit()
    
    return TOTPEnableResponse(
        enabled=True,
        recovery_codes=recovery_codes,
    )


async def verify_totp_code(db: AsyncSession, user: User, code: str) -> tuple[bool, bool]:
    """
    Verify a TOTP or recovery code.
    
    Returns (is_valid, is_recovery_code).
    If recovery code is used, it should be consumed (removed from list).
    """
    # КАО#319: a missing or UNDECRYPTABLE secret must only disable the TOTP branch — never the recovery
    # codes. Both cases used to `return False, False` immediately, so if MESSENGER_TOTP_ENCRYPTION_KEY was
    # ever rotated (or a secret got corrupted) every 2FA user was locked out completely: their authenticator
    # could not work AND their recovery codes — the documented way out of exactly this situation — were
    # unreachable. Fall through instead; the recovery-code check below needs no secret at all.
    plaintext_secret = None
    if user.totp_secret:
        try:
            plaintext_secret = _decrypt_totp_secret(user.totp_secret)
        except Exception as e:
            logger.error(f"[TOTP] Failed to decrypt secret for user {user.id}: {e} — falling back to recovery codes")

    # Try TOTP first (6 digits)
    if plaintext_secret and len(code) == 6 and code.isdigit():
        # КАО#301: single-use — the caller (login / webauthn 2FA) commits, persisting the burnt step.
        if await _consume_totp(db, user, plaintext_secret, code):
            return True, False
    
    # Try recovery code (format: XXXX-XXXX or XXXXXXXX)
    if user.recovery_codes:
        try:
            hashed_codes = json.loads(user.recovery_codes)
            valid, index = verify_recovery_code(code, hashed_codes)
            if valid:
                return True, True
        except json.JSONDecodeError:
            pass
    
    return False, False


async def consume_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
    """
    Remove a used recovery code from the user's list.
    
    Returns True if the code was found and removed.
    """
    if not user.recovery_codes:
        return False

    # КАО#338: lock the row first. This was the same read-modify-write КАО#320 removed for TOTP steps —
    # two concurrent logins could both read the list, both match the same code, and both write back a list
    # with only THEIR entry removed, so a "one-time" recovery code survived and stayed usable.
    # КАО#374: the lock alone did NOT fix it. By this point the User is already in this AsyncSession's
    # identity map (loaded by the login path), and SQLAlchemy returns that SAME instance for an
    # already-loaded, non-expired object WITHOUT overwriting its attributes — the session is created with
    # expire_on_commit=False (database.py), so nothing expires them either. `locked is user`, and
    # user.recovery_codes was still the value read BEFORE the lock. The lock serialised the transactions
    # while each one kept doing a read-modify-write over its own stale list, which is exactly the lost
    # update КАО#338 set out to remove: the loser writes back a list that still contains the code the
    # winner just consumed, so a one-time recovery code survives its own use.
    # populate_existing=True forces the loaded columns to be refreshed from the locked row.
    try:
        locked = (await db.execute(
            select(User).where(User.id == user.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if locked is not None:
            user = locked
    except Exception as e:
        logger.warning(f"[TOTP] recovery-code row lock unavailable: {e}")
    if not user.recovery_codes:
        return False

    try:
        hashed_codes = json.loads(user.recovery_codes)
        valid, index = verify_recovery_code(code, hashed_codes)
        if valid and index >= 0:
            hashed_codes.pop(index)
            user.recovery_codes = json.dumps(hashed_codes)
            await db.commit()
            return True
    except json.JSONDecodeError:
        pass
    
    return False
