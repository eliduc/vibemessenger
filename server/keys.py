"""
Key bundle API endpoints for E2E encryption.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import KeyBundle, KeyBundleCreate, KeyBundleResponse, User
from app.api.auth import get_current_user_id


router = APIRouter(prefix="/keys", tags=["Key Exchange"])


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
    """
    # Check for existing bundle
    result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update existing bundle
        existing.identity_key = bundle.identity_key
        existing.signed_prekey_id = bundle.signed_prekey_id
        existing.signed_prekey = bundle.signed_prekey
        existing.signed_prekey_signature = bundle.signed_prekey_signature
        existing.one_time_prekeys = json.dumps(bundle.one_time_prekeys)
        # v3.11.10: Save signing key and PQ-KEM key
        if bundle.signing_public_key:
            existing.signing_public_key = bundle.signing_public_key
        if bundle.pq_kem_public_key:
            existing.pq_kem_public_key = bundle.pq_kem_public_key
    else:
        # Create new bundle
        new_bundle = KeyBundle(
            user_id=user_id,
            identity_key=bundle.identity_key,
            signed_prekey_id=bundle.signed_prekey_id,
            signed_prekey=bundle.signed_prekey,
            signed_prekey_signature=bundle.signed_prekey_signature,
            one_time_prekeys=json.dumps(bundle.one_time_prekeys),
            signing_public_key=bundle.signing_public_key,
            pq_kem_public_key=bundle.pq_kem_public_key,
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
            detail="User has no key bundle"
        )
    
    # Consume one-time prekey if available
    otps = json.loads(bundle.one_time_prekeys or "[]")
    consumed_otp = None
    
    if otps:
        consumed_otp = otps.pop(0)
        bundle.one_time_prekeys = json.dumps(otps)
        await db.commit()  # Commit to ensure OTP is consumed atomically
        
        # Notify user if prekeys running low
        if len(otps) < 10:
            # TODO: Send push notification or WebSocket message
            pass
    
    return KeyBundleResponse(
        user_id=target_user_id,
        identity_key=bundle.identity_key,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bundle.signed_prekey_signature,
        one_time_prekey=consumed_otp,
        signing_public_key=bundle.signing_public_key,
        pq_kem_public_key=bundle.pq_kem_public_key,
    )


@router.get("/bundle/status/me")
async def get_my_bundle_status(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get status of current user's key bundle.
    
    Returns count of remaining one-time prekeys.
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
    
    return {
        "has_bundle": True,
        "prekeys_remaining": len(otps),
        "signed_prekey_id": bundle.signed_prekey_id,
        "needs_replenishment": len(otps) < 10,
    }
