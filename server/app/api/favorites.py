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
Favorites API endpoints.
"""
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, and_, delete, or_
from sqlalchemy.exc import IntegrityError  # КАО#252 (#36): graceful concurrent/duplicate favorites
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.poll import FavoriteMessage, FavoriteCreate, FavoriteResponse
from app.models.message import Message
from app.models.user import User
from app.api.auth import get_current_user_id

router = APIRouter(prefix="/favorites", tags=["favorites"])


async def get_current_user(user_id: str = Depends(get_current_user_id), db: AsyncSession = Depends(get_db)) -> User:
    """Get current user from database."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.post("", response_model=FavoriteResponse)
async def add_favorite(
    data: FavoriteCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Add a message to favorites."""
    # Check if already favorited
    result = await db.execute(
        select(FavoriteMessage).where(
            and_(
                FavoriteMessage.user_id == user.id,
                FavoriteMessage.message_id == data.message_id
            )
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Return existing favorite
        return FavoriteResponse(
            id=existing.id,
            message_id=existing.message_id,
            chat_id=existing.chat_id,
            group_id=existing.group_id,
            sender_id=existing.sender_id,
            sender_name=existing.sender_name,
            preview_text=existing.preview_text,
            created_at=existing.created_at
        )

    # Create new favorite
    favorite = FavoriteMessage(
        id=str(uuid4()),
        user_id=user.id,
        message_id=data.message_id,
        chat_id=data.chat_id,
        group_id=data.group_id,
        sender_id=data.sender_id,
        sender_name=data.sender_name,
        preview_text=data.preview_text[:2000] if data.preview_text else None  # КАО#231: opaque ciphertext (was [:200] which corrupted it)
    )

    db.add(favorite)
    try:
        await db.commit()
        await db.refresh(favorite)
    except IntegrityError:
        # КАО#252 (#36): concurrent add of the same favorite — return the row that landed.
        await db.rollback()
        existing = (await db.execute(
            select(FavoriteMessage).where(
                and_(FavoriteMessage.user_id == user.id, FavoriteMessage.message_id == data.message_id)
            )
        )).scalar_one_or_none()
        favorite = existing or favorite

    return FavoriteResponse(
        id=favorite.id,
        message_id=favorite.message_id,
        chat_id=favorite.chat_id,
        group_id=favorite.group_id,
        sender_id=favorite.sender_id,
        sender_name=favorite.sender_name,
        preview_text=favorite.preview_text,
        created_at=favorite.created_at
    )


@router.get("", response_model=List[FavoriteResponse])
async def get_favorites(
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's favorite messages, excluding deleted messages."""
    result = await db.execute(
        select(FavoriteMessage)
        .where(FavoriteMessage.user_id == user.id)
        .order_by(FavoriteMessage.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    favorites = result.scalars().all()

    # v3.8.39: Filter out favorites where message was deleted for both parties
    valid_favorites = []
    for f in favorites:
        # Check if message exists and is not fully deleted
        msg_result = await db.execute(
            select(Message).where(Message.id == f.message_id)
        )
        msg = msg_result.scalar_one_or_none()
        
        # Skip if message doesn't exist or is deleted for both sender and recipient
        if msg is None:
            continue
        if msg.deleted_for_sender and msg.deleted_for_recipient:
            continue
            
        valid_favorites.append(f)

    return [
        FavoriteResponse(
            id=f.id,
            message_id=f.message_id,
            chat_id=f.chat_id,
            group_id=f.group_id,
            sender_id=f.sender_id,
            sender_name=f.sender_name,
            preview_text=f.preview_text,
            created_at=f.created_at
        )
        for f in valid_favorites
    ]


@router.get("/count")
async def get_favorites_count(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get count of user's favorites."""
    from sqlalchemy import func
    result = await db.execute(
        select(func.count(FavoriteMessage.id))
        .where(FavoriteMessage.user_id == user.id)
    )
    count = result.scalar()
    return {"count": count}


@router.get("/check/{message_id}")
async def check_favorite(
    message_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Check if a message is favorited."""
    result = await db.execute(
        select(FavoriteMessage).where(
            and_(
                FavoriteMessage.user_id == user.id,
                FavoriteMessage.message_id == message_id
            )
        )
    )
    favorite = result.scalar_one_or_none()
    return {"is_favorite": favorite is not None, "favorite_id": favorite.id if favorite else None}


@router.delete("/{message_id}")
async def remove_favorite(
    message_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Remove a message from favorites."""
    result = await db.execute(
        select(FavoriteMessage).where(
            and_(
                FavoriteMessage.user_id == user.id,
                FavoriteMessage.message_id == message_id
            )
        )
    )
    favorite = result.scalar_one_or_none()

    if not favorite:
        raise HTTPException(status_code=404, detail="Favorite not found")

    await db.delete(favorite)
    await db.commit()

    return {"status": "ok", "message_id": message_id}


@router.delete("")
async def clear_all_favorites(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Clear all favorites for user."""
    await db.execute(
        delete(FavoriteMessage).where(FavoriteMessage.user_id == user.id)
    )
    await db.commit()

    return {"status": "ok", "message": "All favorites cleared"}


# ==================== BATCH OPERATIONS ====================

from pydantic import BaseModel

class BatchFavoriteItem(BaseModel):
    message_id: str
    chat_id: Optional[str] = None
    group_id: Optional[str] = None
    sender_id: str
    sender_name: str
    preview_text: Optional[str] = None


class BatchFavoriteRequest(BaseModel):
    items: List[BatchFavoriteItem]


@router.post("/batch", status_code=status.HTTP_200_OK)
async def batch_add_favorites(
    request: BatchFavoriteRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Add multiple messages to favorites at once.
    Skips messages that are already favorited.

    Returns list of added message IDs and count of skipped (already favorited).
    """
    added = []
    skipped = []
    errors = []
    seen = set()  # КАО#252 (#36): dedup repeated message_ids WITHIN the request

    for item in request.items:
        try:
            if item.message_id in seen:
                skipped.append(item.message_id)
                continue
            seen.add(item.message_id)

            # Check if already favorited
            result = await db.execute(
                select(FavoriteMessage).where(
                    and_(
                        FavoriteMessage.user_id == user.id,
                        FavoriteMessage.message_id == item.message_id
                    )
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                skipped.append(item.message_id)
                continue

            # Create new favorite
            favorite = FavoriteMessage(
                id=str(uuid4()),
                user_id=user.id,
                message_id=item.message_id,
                chat_id=item.chat_id,
                group_id=item.group_id,
                sender_id=item.sender_id,
                sender_name=item.sender_name,
                preview_text=item.preview_text[:2000] if item.preview_text else None  # КАО#231: opaque ciphertext (was [:200] which corrupted it)
            )

            db.add(favorite)
            # КАО#252 (#36): commit per item so one duplicate (race) can't abort the WHOLE batch on
            # the unique constraint — was a single trailing commit that failed the entire request.
            try:
                await db.commit()
                added.append(item.message_id)
            except IntegrityError:
                await db.rollback()
                skipped.append(item.message_id)
        except Exception as e:
            await db.rollback()
            errors.append({"message_id": item.message_id, "error": str(e)})

    return {
        "added": added,
        "added_count": len(added),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "errors": errors,
        "error_count": len(errors)
    }
