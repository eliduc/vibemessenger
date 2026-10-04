"""
Link Preview API - OpenGraph metadata extraction.
"""
import asyncio
import ipaddress
import re
import logging
import socket
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel

from app.api.auth import get_current_user_id
from app.rate_limiter import user_limiter, RATE_LIMIT_PREVIEW

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/preview", tags=["preview"])

# Simple in-memory cache for link previews (TTL: 24 hours)
_preview_cache: dict[str, tuple[dict, datetime]] = {}
CACHE_TTL = timedelta(hours=24)
MAX_CACHE_SIZE = 1000


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved (SSRF protection)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return True  # If we can't parse it, block it


def is_blocked_url(url: str) -> bool:
    """Check if URL points to internal/blocked addresses via DNS resolution."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        
        # Block non-http(s) schemes
        if parsed.scheme not in ('http', 'https'):
            return True
        
        # Block empty hosts
        if not host:
            return True
        
        # Resolve DNS and check all returned IPs
        try:
            addr_infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, socktype, proto, canonname, sockaddr in addr_infos:
                ip = sockaddr[0]
                if _is_private_ip(ip):
                    logger.warning(f"[SSRF] Blocked URL {url}: resolved to private IP {ip}")
                    return True
        except socket.gaierror:
            # DNS resolution failed — block
            return True
            
        return False
    except Exception:
        return True


def _resolve_safe_ip(host: str):
    """КАО#240 (SSRF #2): resolve host once; return (family, ip) only if EVERY resolved address is
    public, else None. Used to PIN the connection IP — defeats the DNS-rebinding / TOCTOU window where
    is_blocked_url() validates one resolution and httpx then re-resolves to a private IP."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    chosen = None
    for family, _socktype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            return None  # any private/reserved resolution → block the whole host
        if chosen is None:
            chosen = (family, ip)
    return chosen


async def _pinned_get(client: "httpx.AsyncClient", url: str):
    """КАО#240 (SSRF #2): GET that connects to a freshly-validated, PINNED IP while preserving the
    original Host header and (for https) the SNI / cert-verification hostname. No second DNS lookup
    happens between validation and connection, so DNS rebinding cannot redirect us to an internal IP."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise HTTPException(status_code=400, detail="URL not allowed")
    host = parsed.hostname or ''
    if not host:
        raise HTTPException(status_code=400, detail="URL not allowed")
    safe = _resolve_safe_ip(host)
    if safe is None:
        logger.warning(f"[SSRF] Blocked (no safe pinned IP) for {url}")
        raise HTTPException(status_code=400, detail="URL not allowed")
    _family, ip = safe
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    ip_host = f"[{ip}]" if ':' in ip else ip  # bracket IPv6 literals
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    ip_url = f"{parsed.scheme}://{ip_host}:{port}{path}"
    host_header = host if (parsed.port in (None, 80, 443)) else f"{host}:{parsed.port}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; VibeMessenger/1.0; +https://vibemessenger.com)',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
        'Host': host_header,
    }
    # For https: keep SNI + certificate verification bound to the real hostname, not the pinned IP.
    extensions = {'sni_hostname': host} if parsed.scheme == 'https' else None
    return await client.get(ip_url, headers=headers, extensions=extensions)


class LinkPreviewResponse(BaseModel):
    url: str
    title: Optional[str] = None
    description: Optional[str] = None
    image: Optional[str] = None
    site_name: Optional[str] = None
    favicon: Optional[str] = None


def extract_og_tag(html: str, property_name: str) -> Optional[str]:
    """Extract OpenGraph tag value from HTML."""
    # Try og: prefix
    patterns = [
        rf'<meta[^>]+property=["\']og:{property_name}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:{property_name}["\']',
        # Twitter cards as fallback
        rf'<meta[^>]+name=["\']twitter:{property_name}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']twitter:{property_name}["\']',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None


def extract_title(html: str) -> Optional[str]:
    """Extract page title."""
    # Try og:title first
    og_title = extract_og_tag(html, 'title')
    if og_title:
        return og_title
    
    # Fallback to <title> tag
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    
    return None


def extract_description(html: str) -> Optional[str]:
    """Extract page description."""
    # Try og:description first
    og_desc = extract_og_tag(html, 'description')
    if og_desc:
        return og_desc
    
    # Fallback to meta description
    patterns = [
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None


def extract_favicon(html: str, base_url: str) -> Optional[str]:
    """Extract favicon URL."""
    patterns = [
        r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            favicon = match.group(1)
            # Make absolute URL
            if favicon.startswith('//'):
                return 'https:' + favicon
            elif favicon.startswith('/'):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{favicon}"
            elif not favicon.startswith('http'):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}/{favicon}"
            return favicon
    
    # Default favicon location
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"


def make_absolute_url(url: str, base_url: str) -> str:
    """Convert relative URL to absolute."""
    if not url:
        return url
    if url.startswith('//'):
        return 'https:' + url
    if url.startswith('/'):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{url}"
    if not url.startswith('http'):
        return base_url.rstrip('/') + '/' + url
    return url


async def fetch_preview(url: str) -> LinkPreviewResponse:
    """Fetch and parse URL for preview data with SSRF protection."""
    # КАО#240 Round-2: the redundant is_blocked_url() pre-check was removed — it did a SEPARATE DNS
    # lookup before _pinned_get did its own, re-opening the DNS-rebinding TOCTOU window. _pinned_get
    # (called for every hop below) resolves+validates+pins atomically, which is the real protection.
    try:
        async with httpx.AsyncClient(
            timeout=5.0,
            follow_redirects=False,  # Manual redirect following with validation
            max_redirects=0,
        ) as client:
            current_url = url
            max_hops = 3

            for _ in range(max_hops):
                # КАО#240 (SSRF #2): pinned GET — resolve+validate+connect atomically (no rebinding window)
                response = await _pinned_get(client, current_url)

                # Handle redirects manually — each hop is re-validated+re-pinned by _pinned_get
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('location')
                    if not location:
                        break
                    # Resolve relative redirects
                    if location.startswith('/'):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith('http'):
                        location = current_url.rstrip('/') + '/' + location

                    current_url = location
                    continue

                break  # Got a non-redirect response
            
            # Only process HTML
            content_type = response.headers.get('content-type', '')
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                return LinkPreviewResponse(
                    url=url,
                    title=urlparse(url).netloc,
                )
            
            html = response.text[:100000]  # Limit to first 100KB
            
            title = extract_title(html)
            description = extract_description(html)
            image = extract_og_tag(html, 'image')
            site_name = extract_og_tag(html, 'site_name')
            favicon = extract_favicon(html, url)
            
            # Make image URL absolute
            if image:
                image = make_absolute_url(image, url)
            
            # Truncate description
            if description and len(description) > 300:
                description = description[:297] + '...'
            
            return LinkPreviewResponse(
                url=url,
                title=title or urlparse(url).netloc,
                description=description,
                image=image,
                site_name=site_name,
                favicon=favicon,
            )
            
    except HTTPException:
        raise  # КАО#240 Round-2: preserve the 400 "URL not allowed" from _pinned_get (was masked as 500)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request timeout")
    except httpx.RequestError as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        raise HTTPException(status_code=502, detail="Failed to fetch URL")
    except Exception as e:
        logger.error(f"Error fetching preview for {url}: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


def cleanup_cache():
    """Remove expired cache entries."""
    global _preview_cache
    now = datetime.now(timezone.utc)
    expired = [k for k, (_, ts) in _preview_cache.items() if now - ts > CACHE_TTL]
    for k in expired:
        del _preview_cache[k]
    
    # Trim if too large
    if len(_preview_cache) > MAX_CACHE_SIZE:
        sorted_items = sorted(_preview_cache.items(), key=lambda x: x[1][1])
        _preview_cache = dict(sorted_items[MAX_CACHE_SIZE // 2:])


@router.get("", response_model=LinkPreviewResponse)
@user_limiter.limit(RATE_LIMIT_PREVIEW)
async def get_link_preview(
    request: Request,
    url: str = Query(..., min_length=10, max_length=2000),
    current_user_id: str = Depends(get_current_user_id),
):
    """
    Get link preview (OpenGraph metadata) for a URL.
    
    Results are cached for 24 hours.
    Rate limited: 30 requests per minute per user.
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Check cache
    cache_key = url.lower()
    if cache_key in _preview_cache:
        data, timestamp = _preview_cache[cache_key]
        if datetime.now(timezone.utc) - timestamp < CACHE_TTL:
            return LinkPreviewResponse(**data)
    
    # Fetch and cache
    preview = await fetch_preview(url)
    
    # Store in cache
    cleanup_cache()
    _preview_cache[cache_key] = (preview.model_dump(), datetime.now(timezone.utc))
    
    return preview
