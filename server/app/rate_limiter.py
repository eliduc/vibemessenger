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
Rate Limiting Module for Secure Messenger.

Provides centralized rate limiting using slowapi.
"""
import ipaddress  # КАО#300: validate the client-supplied CF-Connecting-IP before using it as a bucket key

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

from app.config import settings


def get_request_identifier(request: Request) -> str:
    """
    Get identifier for rate limiting.
    
    Uses user ID if authenticated, otherwise IP address.
    This allows per-user limits for authenticated requests
    and per-IP limits for unauthenticated requests (like login).
    
    IP extraction priority:
    1. CF-Connecting-IP (set by Cloudflare, trusted)
    2. X-Real-IP (set by nginx with real_ip module)
    3. Last IP in X-Forwarded-For (last proxy hop, harder to spoof)
    4. request.client.host (direct connection)
    """
    # Prefer Cloudflare's client IP header.
    # КАО#300: this header is NOT verified here, so only accept a well-formed IP address — otherwise an
    # arbitrary string becomes a rate-limit bucket key (unbounded key space / trivially fresh identity).
    # Deliberately NOT dropped altogether: the edge overwrites (and in practice 403s) a client-supplied
    # CF-Connecting-IP, and nginx independently limits the auth endpoints on $binary_remote_addr, which
    # is not client-controllable. Ignoring the header instead would collapse every tunnelled user into
    # the single cloudflared source IP and rate-limit them as one — a real degradation.
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        candidate = cf_ip.strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass  # malformed → fall through to the trusted nginx-set headers below
    
    # Prefer X-Real-IP set by trusted nginx
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Use LAST hop in X-Forwarded-For (not first — first is client-controlled)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Last IP is the one added by the closest trusted proxy
        ips = [ip.strip() for ip in forwarded.split(",")]
        return ips[-1]
    
    return request.client.host if request.client else "unknown"


def get_user_identifier(request: Request) -> str:
    """
    Get user-based identifier for rate limiting authenticated endpoints.
    Falls back to IP if not authenticated.
    """
    from app.services.auth_service import auth_service
    
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            token = auth_header[7:]
            payload = auth_service.decode_access_token(token)
            return f"user:{payload['sub']}"
        except:
            pass
    
    # Fallback to IP
    return get_request_identifier(request)


# Create limiter instance with IP-based key function (for unauthenticated endpoints)
limiter = Limiter(
    key_func=get_request_identifier,
    default_limits=[settings.rate_limit_default] if settings.rate_limit_enabled else [],
    enabled=settings.rate_limit_enabled,
    storage_uri="memory://",
)

# Create user-based limiter for authenticated endpoints
user_limiter = Limiter(
    key_func=get_user_identifier,
    default_limits=[settings.rate_limit_default] if settings.rate_limit_enabled else [],
    enabled=settings.rate_limit_enabled,
    storage_uri="memory://",
)


# Pre-defined rate limit values from settings
RATE_LIMIT_LOGIN = settings.rate_limit_login
RATE_LIMIT_REGISTER = settings.rate_limit_register
RATE_LIMIT_SEND = settings.rate_limit_send
RATE_LIMIT_PREVIEW = settings.rate_limit_preview
RATE_LIMIT_UPLOAD = settings.rate_limit_upload
