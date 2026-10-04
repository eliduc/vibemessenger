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
Key bundle API endpoints for E2E encryption.
Version: 3.11.0 - Added PQXDH support (ML-KEM-768 post-quantum hybrid key exchange)
"""
import json
import asyncio
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import KeyBundle, KeyBundleCreate, KeyBundleResponse, User
from app.api.auth import get_current_user_id
from app.models.message import WSMessage, WSMessageType

# Threshold for low prekeys warning
LOW_PREKEYS_THRESHOLD = 10


router = APIRouter(prefix="/keys", tags=["Key Exchange"])


async def send_low_prekeys_notification(user_id: str, remaining_count: int):
    """Send LOW_PREKEYS WebSocket notification to user."""
    try:
        from app.services.websocket_manager import ws_manager
        
        message = WSMessage(
            type=WSMessageType.LOW_PREKEYS,
            payload={
                "remaining": remaining_count,
                "threshold": LOW_PREKEYS_THRESHOLD,
                "message": f"Only {remaining_count} one-time prekeys remaining. Please replenish."
            }
        )
        
        # Fire and forget - don't block the response
        asyncio.create_task(ws_manager.send_to_user(user_id, message))
        
    except Exception as e:
        # Don't fail the main request if notification fails
        import logging
        logging.getLogger(__name__).warning(f"Failed to send LOW_PREKEYS notification: {e}")


@router.post("/bundle", status_code=status.HTTP_201_CREATED)
async def upload_key_bundle(
    bundle: KeyBundleCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Upload or update user's key bundle for X3DH.
    
    This should be called:
    - On first registration
    - When signed prekey needs rotation (recommended: weekly)
    - To replenish one-time prekeys
    
    v3.7.0: Supports previous_signed_prekey for rotation
    """
    # Check for existing bundle
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update existing bundle
        existing.identity_key = bundle.identity_key
        
        # Handle signed prekey rotation
        if existing.signed_prekey_id != bundle.signed_prekey_id:
            # New SPK - move current to previous
            existing.previous_signed_prekey_id = existing.signed_prekey_id
            existing.previous_signed_prekey = existing.signed_prekey
            existing.previous_signed_prekey_signature = existing.signed_prekey_signature
            existing.previous_signed_prekey_created_at = existing.signed_prekey_created_at
        
        existing.signed_prekey_id = bundle.signed_prekey_id
        existing.signed_prekey = bundle.signed_prekey
        existing.signed_prekey_signature = bundle.signed_prekey_signature
        existing.signed_prekey_created_at = datetime.now(timezone.utc)
        
        # Handle explicit previous SPK from client (during rotation)
        if bundle.previous_signed_prekey_id is not None:
            existing.previous_signed_prekey_id = bundle.previous_signed_prekey_id
            existing.previous_signed_prekey = bundle.previous_signed_prekey
            existing.previous_signed_prekey_signature = bundle.previous_signed_prekey_signature
        
        existing.one_time_prekeys = json.dumps(bundle.one_time_prekeys)
        
        # v3.11.0: Update PQ-KEM key if provided
        if bundle.pq_kem_public_key is not None:
            existing.pq_kem_public_key = bundle.pq_kem_public_key
        
        # v3.11.8: Update signing public key if provided
        if bundle.signing_public_key is not None:
            existing.signing_public_key = bundle.signing_public_key
    else:
        # Create new bundle
        new_bundle = KeyBundle(
            user_id=user_id,
            identity_key=bundle.identity_key,
            signed_prekey_id=bundle.signed_prekey_id,
            signed_prekey=bundle.signed_prekey,
            signed_prekey_signature=bundle.signed_prekey_signature,
            signed_prekey_created_at=datetime.now(timezone.utc),
            one_time_prekeys=json.dumps(bundle.one_time_prekeys),
            pq_kem_public_key=bundle.pq_kem_public_key,  # v3.11.0: PQ-KEM
            signing_public_key=bundle.signing_public_key,  # v3.11.8: Ed25519
        )
        db.add(new_bundle)
    
    await db.commit()
    return {"status": "ok", "prekeys_count": len(bundle.one_time_prekeys)}


@router.post("/bundle/prekeys")
async def add_one_time_prekeys(
    prekeys: list[dict],
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Add more one-time prekeys to existing bundle.
    
    Should be called when server notifies that prekeys are running low.
    """
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    bundle = result.scalar_one_or_none()
    
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key bundle not found. Upload full bundle first."
        )
    
    existing = json.loads(bundle.one_time_prekeys or "[]")
    existing.extend(prekeys)
    bundle.one_time_prekeys = json.dumps(existing)
    
    await db.commit()
    return {"status": "ok", "total_prekeys": len(existing)}


@router.get("/bundle/{target_user_id}", response_model=KeyBundleResponse)
async def get_key_bundle(
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Fetch another user's key bundle for initiating encrypted session.
    
    One one-time prekey is consumed (removed from server) per request.
    If no OTPs available, session can still be established using signed prekey only.
    
    v3.7.0: Sends LOW_PREKEYS notification when OTPs are low.
    """
    # Verify target user exists
    result = await db.execute(
        select(User).where(User.id == target_user_id)
    )
    target_user = result.scalar_one_or_none()
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get key bundle WITH row lock to prevent OTP race condition.
    # Two concurrent requests will serialize here, ensuring each gets a unique OTP.
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == target_user_id).with_for_update()
    )
    bundle = result.scalar_one_or_none()
    
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User has no key bundle"
        )
    
    # Consume one-time prekey if available
    otps = json.loads(bundle.one_time_prekeys or "[]")
    consumed_otp = None
    
    if otps:
        consumed_otp = otps.pop(0)
        bundle.one_time_prekeys = json.dumps(otps)
        await db.commit()  # Commit to ensure OTP is consumed atomically
        
        # v3.7.0: Send notification if prekeys running low
        if len(otps) < LOW_PREKEYS_THRESHOLD:
            await send_low_prekeys_notification(target_user_id, len(otps))
    
    # Build response with optional previous SPK
    response = KeyBundleResponse(
        user_id=target_user_id,
        identity_key=bundle.identity_key,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bundle.signed_prekey_signature,
        one_time_prekey=consumed_otp,
        pq_kem_public_key=bundle.pq_kem_public_key,  # v3.11.0: PQ-KEM
        signing_public_key=bundle.signing_public_key,  # v3.11.8: Ed25519
    )
    
    # Include previous SPK if available (for in-flight messages during rotation)
    if bundle.previous_signed_prekey_id is not None:
        # Only include if not too old (14 days max)
        if bundle.previous_signed_prekey_created_at:
            age = datetime.now(timezone.utc) - bundle.previous_signed_prekey_created_at
            if age < timedelta(days=14):
                response.previous_signed_prekey_id = bundle.previous_signed_prekey_id
                response.previous_signed_prekey = bundle.previous_signed_prekey
                response.previous_signed_prekey_signature = bundle.previous_signed_prekey_signature
    
    return response


@router.get("/bundle/status/me")
async def get_my_bundle_status(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get status of current user's key bundle.
    
    Returns count of remaining one-time prekeys and SPK age.
    v3.7.0: Added signed_prekey_age_days for rotation check.
    """
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    bundle = result.scalar_one_or_none()
    
    if not bundle:
        return {
            "has_bundle": False,
            "prekeys_remaining": 0,
        }
    
    otps = json.loads(bundle.one_time_prekeys or "[]")
    
    # Calculate SPK age
    spk_age_days = None
    if bundle.signed_prekey_created_at:
        age = datetime.now(timezone.utc) - bundle.signed_prekey_created_at
        spk_age_days = age.days
    
    return {
        "has_bundle": True,
        "prekeys_remaining": len(otps),
        "signed_prekey_id": bundle.signed_prekey_id,
        "signed_prekey_age_days": spk_age_days,
        "needs_replenishment": len(otps) < LOW_PREKEYS_THRESHOLD,
        "needs_spk_rotation": spk_age_days is not None and spk_age_days >= 7,
        "has_pq_key": bundle.pq_kem_public_key is not None,  # v3.11.0
    }


# ==============================================================================
# KEY RESET NOTIFICATION (v3.8.6)
# ==============================================================================

@router.post("/reset")
async def notify_key_reset(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Notify all contacts that user has reset their E2EE keys.
    
    v3.8.6: This should be called after resetE2EE() on client.
    
    All contacts will receive KEY_RESET WebSocket notification and should
    delete their local session with this user.
    
    Next message exchange will either:
    - Establish new E2EE session (if both have key bundles)
    - Fall back to plaintext with user confirmation
    """
    from app.services.websocket_manager import ws_manager
    from app.models.message import Message
    from sqlalchemy import or_, distinct
    
    # Get current user info
    result = await db.execute(select(User).where(User.id == user_id))
    current_user = result.scalar_one_or_none()
    
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Find all contacts (users we've exchanged messages with)
    contacts_query = await db.execute(
        select(distinct(Message.recipient_id)).where(
            Message.sender_id == user_id,
            Message.recipient_id != None
        )
    )
    sent_to = {row[0] for row in contacts_query.fetchall()}
    
    received_query = await db.execute(
        select(distinct(Message.sender_id)).where(
            Message.recipient_id == user_id
        )
    )
    received_from = {row[0] for row in received_query.fetchall()}
    
    all_contacts = sent_to | received_from
    all_contacts.discard(user_id)  # Remove self
    
    # Send KEY_RESET notification to all online contacts
    notified = 0
    for contact_id in all_contacts:
        message = WSMessage(
            type=WSMessageType.KEY_RESET,
            payload={
                "user_id": user_id,
                "username": current_user.username,
                "display_name": current_user.display_name,
                "message": f"{current_user.display_name or current_user.username} has reset their encryption keys"
            }
        )
        delivered = await ws_manager.send_to_user(contact_id, message)
        if delivered:
            notified += 1
    
    return {
        "status": "ok",
        "contacts_found": len(all_contacts),
        "contacts_notified": notified,
        "message": "Contacts have been notified about key reset"
    }


# ==============================================================================
# KEY VERIFICATION ENDPOINTS
# ==============================================================================

@router.get("/identity/me")
async def get_my_identity_key(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get current user's own identity public key.
    
    Used for displaying own safety number in verification UI.
    """
    # Get current user
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    current_user = result.scalar_one_or_none()
    
    # Get key bundle
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    bundle = result.scalar_one_or_none()
    
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="You have no encryption keys"
        )
    
    return {
        "user_id": user_id,
        "identity_key": bundle.identity_key,
        "username": current_user.username if current_user else None,
        "display_name": current_user.display_name if current_user else None,
    }


@router.get("/identity/{target_user_id}")
async def get_identity_key(
    target_user_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get another user's identity public key for verification.
    
    Unlike /bundle/{user_id}, this endpoint:
    - Does NOT consume one-time prekeys
    - Returns only identity_key for safety number generation
    - Can be called multiple times safely
    
    Used for key verification (comparing safety numbers).
    """
    # Verify target user exists
    result = await db.execute(
        select(User).where(User.id == target_user_id)
    )
    target_user = result.scalar_one_or_none()
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get key bundle
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == target_user_id)
    )
    bundle = result.scalar_one_or_none()
    
    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User has no encryption keys"
        )
    
    return {
        "user_id": target_user_id,
        "identity_key": bundle.identity_key,
        "username": target_user.username,
        "display_name": target_user.display_name,
    }


# ==============================================================================
# SELF ENCRYPTION KEY ENDPOINTS (v3.7.27 - Multi-device sync)
# ==============================================================================

def _validate_wrapped_self_key(key_base64: str):
    """
    v3.11.9: Validate that a self-encryption key is in wrapped (AES-GCM) format.
    Wrapped format: base64(nonce[12] + ciphertext[32] + tag[16]) = 60 bytes → 80 base64 chars.
    Rejects plaintext 32-byte keys (44 base64 chars) to prevent downgrade.
    """
    import base64
    try:
        raw = base64.b64decode(key_base64)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="self_encryption_key is not valid base64"
        )
    
    if len(raw) == 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Plaintext self-encryption keys are no longer accepted. Key must be wrapped (AES-GCM)."
        )
    
    if len(raw) != 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid wrapped key length: {len(raw)} bytes, expected 60 (12 nonce + 48 ciphertext+tag)"
        )

@router.get("/self-key")
async def get_self_encryption_key(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get user's self-encryption key for multi-device sync.
    
    This key is shared across all devices of the same user and is used
    to encrypt messages for self (so other devices can decrypt them).
    
    Returns null if no key exists yet (first device should generate and save it).
    """
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "self_encryption_key": user.self_encryption_key,
        "has_key": user.self_encryption_key is not None,
    }


@router.post("/self-key")
async def save_self_encryption_key(
    data: dict,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Save user's self-encryption key.
    
    This should only be called once (by the first device to initialize E2EE).
    If a key already exists, it will NOT be overwritten (to prevent sync issues).
    
    Body: {"self_encryption_key": "base64-encoded-32-bytes"}
    """
    self_key = data.get("self_encryption_key")
    if not self_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="self_encryption_key is required"
        )
    
    # v3.11.9: Validate wrapped key format (reject plaintext 32-byte keys)
    _validate_wrapped_self_key(self_key)
    
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Only save if no key exists yet
    if user.self_encryption_key is not None:
        return {
            "status": "exists",
            "message": "Self-encryption key already exists. Use existing key.",
            "self_encryption_key": user.self_encryption_key,
        }
    
    user.self_encryption_key = self_key
    await db.commit()
    
    return {
        "status": "created",
        "message": "Self-encryption key saved successfully",
    }


@router.post("/self-key/rewrap")
async def rewrap_self_encryption_key(
    data: dict,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    v3.11.8: Replace existing self-encryption key with a wrapped (encrypted) version.
    
    Called by client when it detects a legacy plaintext key on the server
    and re-wraps it with an identity-derived wrapping key.
    
    Body: {"self_encryption_key": "base64-encoded-wrapped-key"}
    """
    new_key = data.get("self_encryption_key")
    if not new_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="self_encryption_key is required"
        )
    
    # v3.11.9: Validate wrapped key format (reject plaintext 32-byte keys)
    _validate_wrapped_self_key(new_key)
    
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.self_encryption_key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No existing key to rewrap"
        )
    
    user.self_encryption_key = new_key
    await db.commit()
    
    return {
        "status": "rewrapped",
        "message": "Self-encryption key re-wrapped successfully",
    }
