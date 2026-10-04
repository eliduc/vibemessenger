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
Push notification API endpoints.
"""
import re
import socket
from urllib.parse import urlparse
import ipaddress
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel, field_validator
from app.database import get_db
from app.api.auth import get_current_user_id
from app.models.user import PushSubscription
from app.config import settings

router = APIRouter(prefix="/push", tags=["Push Notifications"])


# Known push service domains (whitelist)
ALLOWED_PUSH_DOMAINS = {
    # Google FCM
    'fcm.googleapis.com',
    'android.googleapis.com',
    # Mozilla
    'push.services.mozilla.com',
    'updates.push.services.mozilla.com',
    # Apple
    'api.push.apple.com',
    # Microsoft
    'notify.windows.com',
    'wns.windows.com',
    # Web Push providers
    'web.push.apple.com',
}


def _ip_is_private(ip: "ipaddress._BaseAddress") -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_reserved
            or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def is_private_ip(hostname: str) -> bool:
    """КАО#241 (SSRF #3): block if the hostname is a private IP literal OR RESOLVES to one.
    Previously a domain that resolves to an internal IP (e.g. evil.example.com → 127.0.0.1) passed,
    letting a crafted push subscription drive the server's push-send at an internal address."""
    # Literal IP?
    try:
        return _ip_is_private(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    # Obvious localhost names
    if hostname.lower() in ('localhost', 'localhost.localdomain'):
        return True
    # Resolve and check EVERY returned address; block on resolution failure
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return True
    for _family, _st, _proto, _canon, sockaddr in infos:
        try:
            if _ip_is_private(ipaddress.ip_address(sockaddr[0])):
                return True
        except ValueError:
            return True
    return False


def validate_push_endpoint(endpoint: str) -> tuple[bool, str | None]:
    """
    Validate push endpoint URL for SSRF protection.
    
    Returns (is_valid, error_message).
    """
    if not endpoint:
        return False, "Endpoint is required"
    
    # Must be HTTPS
    if not endpoint.startswith('https://'):
        return False, "Endpoint must use HTTPS"
    
    try:
        parsed = urlparse(endpoint)
    except Exception:
        return False, "Invalid endpoint URL"
    
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid endpoint hostname"
    
    # Block private/local IPs
    if is_private_ip(hostname):
        return False, "Private or local addresses not allowed"
    
    # Check against whitelist (if configured)
    # For flexibility, we allow any public HTTPS endpoint by default
    # but log a warning if not in whitelist
    # In strict mode, uncomment the check below:
    # if hostname not in ALLOWED_PUSH_DOMAINS and not any(hostname.endswith('.' + d) for d in ALLOWED_PUSH_DOMAINS):
    #     return False, "Push endpoint domain not allowed"
    
    return True, None


class PushSubscriptionCreate(BaseModel):
    endpoint: str
    keys: dict  # p256dh and auth keys
    
    @field_validator('endpoint')
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        is_valid, error_msg = validate_push_endpoint(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v


class VapidKeyResponse(BaseModel):
    public_key: str


@router.get("/vapid-key", response_model=VapidKeyResponse)
async def get_vapid_key():
    """Get VAPID public key for push subscription."""
    if not settings.vapid_public_key:
        raise HTTPException(status_code=503, detail="Push notifications not configured")
    return {"public_key": settings.vapid_public_key}


@router.post("/subscribe")
async def subscribe_push(
    subscription: PushSubscriptionCreate,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Subscribe to push notifications."""
    # Check if subscription already exists
    result = await db.execute(
        select(PushSubscription).where(
            PushSubscription.user_id == user_id,
            PushSubscription.endpoint == subscription.endpoint
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update keys
        existing.p256dh = subscription.keys.get('p256dh', '')
        existing.auth = subscription.keys.get('auth', '')
    else:
        # Create new subscription
        push_sub = PushSubscription(
            user_id=user_id,
            endpoint=subscription.endpoint,
            p256dh=subscription.keys.get('p256dh', ''),
            auth=subscription.keys.get('auth', ''),
        )
        db.add(push_sub)
    
    await db.commit()
    return {"message": "Subscribed to push notifications"}


@router.post("/unsubscribe")
async def unsubscribe_push(
    subscription: PushSubscriptionCreate,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Unsubscribe from push notifications."""
    await db.execute(
        delete(PushSubscription).where(
            PushSubscription.user_id == user_id,
            PushSubscription.endpoint == subscription.endpoint
        )
    )
    await db.commit()
    return {"message": "Unsubscribed from push notifications"}


@router.delete("/clear-all")
async def clear_all_subscriptions(
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Clear all push subscriptions for current user.
    
    Use this endpoint to force re-subscription after VAPID key change
    or when push notifications stop working.
    """
    result = await db.execute(
        delete(PushSubscription).where(PushSubscription.user_id == user_id)
    )
    await db.commit()
    
    deleted_count = result.rowcount
    return {
        "message": f"Cleared {deleted_count} push subscription(s)",
        "deleted_count": deleted_count
    }
