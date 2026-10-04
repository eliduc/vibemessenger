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
User Settings API - Mute chats and Block users.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status, Request
from sqlalchemy import select, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database import get_db, Base, TimestampMixin
from app.api.auth import get_current_user_id, get_current_user
from app.models.user import User
from sqlalchemy import Column, String, DateTime, ForeignKey, func
from app.services.audit_service import audit_service as audit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["settings"])


# ============== Database Models ==============

class MutedChat(Base):
    """Muted chat settings."""
    __tablename__ = "muted_chats"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    chat_id = Column(String(36), nullable=False, index=True)  # user_id or group_id
    muted_until = Column(DateTime(timezone=True), nullable=True)  # NULL = forever
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserBlock(Base):
    """User block (personal, not admin)."""
    __tablename__ = "user_blocks"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    blocker_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    blocked_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ============== Pydantic Schemas ==============

class MuteRequest(BaseModel):
    chat_id: str = Field(..., min_length=1, max_length=100, description="Chat ID (user_id or group_id)")
    duration_hours: Optional[int] = Field(None, ge=0, le=8760, description="None=forever, 0=unmute, 1-8760=hours")


class MuteResponse(BaseModel):
    chat_id: str
    muted: bool
    muted_until: Optional[datetime] = None


class MutedChatsResponse(BaseModel):
    muted_chats: list[MuteResponse]


class BlockRequest(BaseModel):
    user_id: str = Field(..., min_length=36, max_length=36, description="User UUID to block")


class BlockResponse(BaseModel):
    user_id: str
    blocked: bool


class BlockedUsersResponse(BaseModel):
    blocked_users: list[str]


# ============== Mute Endpoints ==============

@router.post("/mute", response_model=MuteResponse)
async def mute_chat(
    request: MuteRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Mute a chat (direct or group).
    
    - duration_hours=None: mute forever
    - duration_hours=0: unmute
    - duration_hours>0: mute for specified hours
    """
    chat_id = request.chat_id
    
    # Check if already muted
    existing = await db.execute(
        select(MutedChat).where(
            and_(
                MutedChat.user_id == current_user_id,
                MutedChat.chat_id == chat_id
            )
        )
    )
    muted_chat = existing.scalar_one_or_none()
    
    # Unmute
    if request.duration_hours == 0:
        if muted_chat:
            await db.delete(muted_chat)
            await db.commit()
        return MuteResponse(chat_id=chat_id, muted=False)
    
    # Calculate muted_until
    muted_until = None
    if request.duration_hours and request.duration_hours > 0:
        from datetime import timedelta
        muted_until = datetime.now(timezone.utc) + timedelta(hours=request.duration_hours)
    
    if muted_chat:
        # Update existing
        muted_chat.muted_until = muted_until
    else:
        # Create new
        muted_chat = MutedChat(
            user_id=current_user_id,
            chat_id=chat_id,
            muted_until=muted_until,
        )
        db.add(muted_chat)
    
    await db.commit()
    
    return MuteResponse(
        chat_id=chat_id,
        muted=True,
        muted_until=muted_until,
    )


@router.delete("/mute/{chat_id}")
async def unmute_chat(
    chat_id: str,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Unmute a chat."""
    await db.execute(
        delete(MutedChat).where(
            and_(
                MutedChat.user_id == current_user_id,
                MutedChat.chat_id == chat_id
            )
        )
    )
    await db.commit()
    return {"status": "ok", "chat_id": chat_id, "muted": False}


@router.get("/muted", response_model=MutedChatsResponse)
async def get_muted_chats(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get list of muted chats."""
    result = await db.execute(
        select(MutedChat).where(MutedChat.user_id == current_user_id)
    )
    muted_chats = result.scalars().all()
    
    now = datetime.now(timezone.utc)
    response = []
    
    for mc in muted_chats:
        # Check if mute expired
        if mc.muted_until and mc.muted_until < now:
            # Expired - remove
            await db.delete(mc)
            continue
        
        response.append(MuteResponse(
            chat_id=mc.chat_id,
            muted=True,
            muted_until=mc.muted_until,
        ))
    
    await db.commit()
    return MutedChatsResponse(muted_chats=response)


@router.get("/muted/{chat_id}")
async def check_muted(
    chat_id: str,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Check if a specific chat is muted."""
    result = await db.execute(
        select(MutedChat).where(
            and_(
                MutedChat.user_id == current_user_id,
                MutedChat.chat_id == chat_id
            )
        )
    )
    muted_chat = result.scalar_one_or_none()
    
    if not muted_chat:
        return {"chat_id": chat_id, "muted": False}
    
    # Check expiration
    now = datetime.now(timezone.utc)
    if muted_chat.muted_until and muted_chat.muted_until < now:
        await db.delete(muted_chat)
        await db.commit()
        return {"chat_id": chat_id, "muted": False}
    
    return {
        "chat_id": chat_id,
        "muted": True,
        "muted_until": muted_chat.muted_until.isoformat() if muted_chat.muted_until else None
    }


# ============== Block Endpoints ==============

@router.post("/block", response_model=BlockResponse)
async def block_user(
    http_request: Request,
    request: BlockRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Block a user (personal block, not admin)."""
    blocked_id = request.user_id
    
    # Can't block yourself
    if blocked_id == current_user_id:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    
    # Check user exists
    user = await db.execute(select(User).where(User.id == blocked_id))
    if not user.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get current user for audit log
    current_user_result = await db.execute(select(User).where(User.id == current_user_id))
    current_user = current_user_result.scalar_one_or_none()
    
    # Check if already blocked
    existing = await db.execute(
        select(UserBlock).where(
            and_(
                UserBlock.blocker_id == current_user_id,
                UserBlock.blocked_id == blocked_id
            )
        )
    )
    
    if existing.scalar_one_or_none():
        return BlockResponse(user_id=blocked_id, blocked=True)
    
    # Create block
    block = UserBlock(
        blocker_id=current_user_id,
        blocked_id=blocked_id,
    )
    db.add(block)
    
    # Log block action
    await audit.log_user_blocked(
        db=db,
        blocker_id=current_user_id,
        blocker_username=current_user.username if current_user else "unknown",
        blocked_id=blocked_id,
        request=http_request,
    )
    await db.commit()
    
    logger.info(f"User {current_user_id} blocked {blocked_id}")
    
    return BlockResponse(user_id=blocked_id, blocked=True)


@router.delete("/block/{user_id}")
async def unblock_user(
    user_id: str,
    http_request: Request,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Unblock a user."""
    # Get current user for audit log
    current_user_result = await db.execute(select(User).where(User.id == current_user_id))
    current_user = current_user_result.scalar_one_or_none()
    
    result = await db.execute(
        delete(UserBlock).where(
            and_(
                UserBlock.blocker_id == current_user_id,
                UserBlock.blocked_id == user_id
            )
        )
    )
    
    # Log unblock action if something was deleted
    if result.rowcount > 0:
        await audit.log_user_unblocked(
            db=db,
            blocker_id=current_user_id,
            blocker_username=current_user.username if current_user else "unknown",
            blocked_id=user_id,
            request=http_request,
        )
    
    await db.commit()
    
    logger.info(f"User {current_user_id} unblocked {user_id}")
    
    return {"status": "ok", "user_id": user_id, "blocked": False}


@router.get("/blocked", response_model=BlockedUsersResponse)
async def get_blocked_users(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get list of blocked user IDs."""
    result = await db.execute(
        select(UserBlock.blocked_id).where(UserBlock.blocker_id == current_user_id)
    )
    blocked_ids = [row[0] for row in result.fetchall()]
    
    return BlockedUsersResponse(blocked_users=blocked_ids)


@router.get("/blocked/{user_id}")
async def check_blocked(
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Check if a specific user is blocked."""
    result = await db.execute(
        select(UserBlock).where(
            and_(
                UserBlock.blocker_id == current_user_id,
                UserBlock.blocked_id == user_id
            )
        )
    )
    is_blocked = result.scalar_one_or_none() is not None
    
    return {"user_id": user_id, "blocked": is_blocked}


@router.get("/blocked-by/{user_id}")
async def check_blocked_by(
    user_id: str,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Check if current user is blocked by another user."""
    result = await db.execute(
        select(UserBlock).where(
            and_(
                UserBlock.blocker_id == user_id,
                UserBlock.blocked_id == current_user_id
            )
        )
    )
    is_blocked_by = result.scalar_one_or_none() is not None
    
    return {"user_id": user_id, "blocked_by": is_blocked_by}
