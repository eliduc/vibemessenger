"""
Secure Messenger Server - Main Application
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import init_db, close_db, async_session_maker
from app.rate_limiter import limiter, user_limiter
# Import models to ensure they're registered with SQLAlchemy
from app.models import User, Message, Group, GroupMember, GroupInvite, KeyBundle, PushSubscription, FileMetadata, Poll, PollVote, FavoriteMessage, AuditLog, WebAuthnCredential
from app.api import auth, keys, messages, files, push, admin, groups, webrtc, totp, polls, favorites, export, preview, user_settings, webauthn_api
from app.api.auth import get_current_user_id
from app.services.websocket_manager import ws_manager, websocket_endpoint
from app.services.auth_service import auth_service


# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Background task for cleaning expired messages
async def cleanup_expired_messages():
    """Periodically delete expired messages."""
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute
            async with async_session_maker() as session:
                result = await session.execute(
                    delete(Message).where(
                        Message.expires_at.isnot(None),
                        Message.expires_at < datetime.now(timezone.utc)
                    )
                )
                if result.rowcount > 0:
                    await session.commit()
                    logger.info(f"Deleted {result.rowcount} expired messages")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error cleaning expired messages: {e}")


async def cleanup_unattached_files():
    """Periodically delete unattached files older than TTL (24 hours)."""
    from app.api.files import cleanup_unattached_files as do_cleanup
    
    while True:
        try:
            await asyncio.sleep(3600)  # Check every hour
            async with async_session_maker() as session:
                deleted = await do_cleanup(session)
                if deleted > 0:
                    logger.info(f"File GC: Cleaned up {deleted} unattached files")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in file garbage collection: {e}")


cleanup_task = None
file_gc_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global cleanup_task, file_gc_task
    
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Create data directories
    Path("./data").mkdir(exist_ok=True)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Start WebSocket manager
    await ws_manager.start()
    
    # Start cleanup tasks
    cleanup_task = asyncio.create_task(cleanup_expired_messages())
    logger.info("Expired messages cleanup task started")
    
    file_gc_task = asyncio.create_task(cleanup_unattached_files())
    logger.info("File garbage collection task started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    if file_gc_task:
        file_gc_task.cancel()
        try:
            await file_gc_task
        except asyncio.CancelledError:
            pass
    await ws_manager.stop()
    await close_db()


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="End-to-end encrypted messaging server",
    lifespan=lifespan,
)

# Add rate limiter to app state
app.state.limiter = limiter
app.state.user_limiter = user_limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# CORS middleware
# Parse CORS origins from config (comma-separated string)
cors_origins = []
if settings.cors_origins:
    cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else [],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(totp.router, prefix="/api/v1")
app.include_router(keys.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1")
app.include_router(files.router, prefix="/api/v1")
app.include_router(push.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(groups.router, prefix="/api/v1")
app.include_router(polls.router, prefix="/api/v1")
app.include_router(favorites.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")
app.include_router(preview.router, prefix="/api/v1")
app.include_router(user_settings.router, prefix="/api/v1")
app.include_router(webauthn_api.router, prefix="/api/v1")
app.include_router(webrtc.router, prefix="/api/v1")

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/health")
async def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "online_users": len(ws_manager.get_online_users()),
    }


@app.websocket("/ws")
async def websocket_route(websocket: WebSocket):
    """
    WebSocket endpoint for real-time messaging.
    
    Client must provide JWT token via Sec-WebSocket-Protocol header.
    Format: 'access_token, Bearer.{JWT_TOKEN}'
    
    Example client code:
        new WebSocket(url, ['access_token', 'Bearer.' + token])
    """
    try:
        # Extract token from Sec-WebSocket-Protocol
        # Client sends: ['access_token', 'Bearer.eyJ...']
        subprotocols = websocket.scope.get('subprotocols', [])
        
        token = None
        for protocol in subprotocols:
            if protocol.startswith('Bearer.'):
                token = protocol[7:]  # Remove 'Bearer.' prefix
                break
        
        if not token:
            logger.warning("WebSocket connection without token in subprotocol")
            await websocket.close(code=4001, reason="Missing authentication token")
            return
        
        # Validate token
        payload = auth_service.decode_access_token(token)
        user_id = payload["sub"]
        device_id = payload.get("device_id")

        # КАО#010 (SER#24): enforce session revocation + active/blocked status for WS
        from app.database import async_session_maker
        from app.models.user import User as _User, RefreshToken as _RT
        from sqlalchemy import select as _select, and_ as _and
        _jti = payload.get("jti")
        async with async_session_maker() as _db:
            if _jti:
                _tok = await _db.execute(
                    _select(_RT).where(_and(_RT.access_token_jti == _jti, _RT.is_revoked == False))
                )
                if not _tok.scalar_one_or_none():
                    await websocket.close(code=4001, reason="Session revoked")
                    return
            _ures = await _db.execute(_select(_User).where(_User.id == user_id))
            _uobj = _ures.scalar_one_or_none()
            if not _uobj or not _uobj.is_active or _uobj.is_blocked:
                await websocket.close(code=4001, reason="Account not active")
                return

        # Accept connection with the access_token subprotocol
        await websocket.accept(subprotocol='access_token')
        
        # Handle WebSocket connection
        await websocket_endpoint(websocket, user_id, device_id, already_accepted=True)
        
    except HTTPException as e:
        await websocket.close(code=4001, reason=e.detail)
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        await websocket.close(code=4000, reason="Internal error")


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Custom HTTP exception handler."""
    # КАО#316: forward exc.headers. Endpoints signal machine-readable state through headers — notably
    # `X-TOTP-Required` on the WebAuthn/passkey login path — and dropping them here left the client with
    # no way to know a TOTP code was needed, so passkey login for 2FA users dead-ended.
    # КАО#317: emit BOTH `error` and `detail`. This handler renamed FastAPI's standard `detail` field to
    # `error`, but client code (e.g. the password-login TOTP prompt) still tested `data.detail`, so the
    # 2FA prompt never appeared. Sending both keeps existing readers of either name working.
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """General exception handler."""
    logger.exception(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
