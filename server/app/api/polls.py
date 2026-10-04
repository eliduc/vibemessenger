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
Poll API endpoints.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func, and_
from sqlalchemy.exc import IntegrityError  # КАО#251 (#24): graceful concurrent-vote handling
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.poll import Poll, PollVote, PollCreate, PollVoteRequest, PollResponse, PollOptionResult
from app.models.user import User
from app.api.auth import get_current_user_id
from app.services.websocket_manager import ws_manager
from app.models.message import WSMessage, WSMessageType
import asyncio

router = APIRouter(prefix="/polls", tags=["polls"])


async def get_current_user(user_id: str = Depends(get_current_user_id), db: AsyncSession = Depends(get_db)) -> User:
    """Get current user from database."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def build_poll_response(poll: Poll, votes: List[PollVote], current_user_id: str) -> PollResponse:
    """Build poll response with results."""
    # Count votes per option
    option_votes = {i: [] for i in range(len(poll.options))}
    total_voters = set()
    user_selections = None
    user_voted = False
    
    for vote in votes:
        total_voters.add(vote.user_id)
        if vote.user_id == current_user_id:
            user_voted = True
            user_selections = vote.selected_options
        for opt_idx in vote.selected_options:
            if opt_idx < len(poll.options):
                option_votes[opt_idx].append(vote.user_id)
    
    total_votes = len(total_voters)
    
    # Build results
    results = []
    for i, option_text in enumerate(poll.options):
        voters = option_votes.get(i, [])
        vote_count = len(voters)
        percentage = (vote_count / total_votes * 100) if total_votes > 0 else 0
        
        result = PollOptionResult(
            index=i,
            text=option_text,
            votes=vote_count,
            percentage=round(percentage, 1),
            voters=voters if not poll.is_anonymous else None
        )
        results.append(result)
    
    return PollResponse(
        id=poll.id,
        question=poll.question,
        options=poll.options,
        is_anonymous=poll.is_anonymous,
        is_multiple=poll.is_multiple,
        expires_at=poll.expires_at,
        is_closed=poll.is_closed,
        creator_id=poll.creator_id,
        message_id=poll.message_id,
        total_votes=total_votes,
        results=results,
        user_voted=user_voted,
        user_selections=user_selections,
        created_at=poll.created_at
    )


async def _verify_poll_access(db: AsyncSession, poll: Poll, user_id: str):
    """КАО#006: ensure caller participates in the poll's group/DM (prevents IDOR)."""
    if poll.group_id:
        from app.models.group import GroupMember
        m = await db.execute(
            select(GroupMember).where(
                and_(GroupMember.group_id == poll.group_id, GroupMember.user_id == user_id)
            )
        )
        if not m.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Not a member of this group")
    elif poll.chat_id:
        if user_id not in (poll.creator_id, poll.chat_id):
            raise HTTPException(status_code=403, detail="Access denied")
    elif user_id != poll.creator_id:
        raise HTTPException(status_code=403, detail="Access denied")


@router.post("", response_model=PollResponse)
async def create_poll(
    data: PollCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new poll."""
    # Validate options
    if len(data.options) < 2:
        raise HTTPException(status_code=400, detail="Poll must have at least 2 options")
    if len(data.options) > 10:
        raise HTTPException(status_code=400, detail="Poll cannot have more than 10 options")
    
    # Validate target
    if not data.chat_id and not data.group_id:
        raise HTTPException(status_code=400, detail="Either chat_id or group_id is required")

    # КАО#006: enforce group membership when creating a group poll
    if data.group_id:
        from app.models.group import GroupMember
        gm = await db.execute(
            select(GroupMember).where(
                and_(GroupMember.group_id == data.group_id, GroupMember.user_id == user.id)
            )
        )
        if not gm.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Not a member of this group")

    # Calculate expiration
    expires_at = None
    if data.expires_in_minutes:
        expires_at = datetime.utcnow() + timedelta(minutes=data.expires_in_minutes)
    
    # Create poll
    poll = Poll(
        id=str(uuid4()),
        chat_id=data.chat_id,
        group_id=data.group_id,
        creator_id=user.id,
        question=data.question,
        options=data.options,
        is_anonymous=data.is_anonymous,
        is_multiple=data.is_multiple,
        expires_at=expires_at,
        is_closed=False
    )
    
    db.add(poll)
    await db.commit()
    await db.refresh(poll)
    
    return build_poll_response(poll, [], user.id)


@router.get("/{poll_id}", response_model=PollResponse)
async def get_poll(
    poll_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get poll with results."""
    result = await db.execute(
        select(Poll).options(selectinload(Poll.votes)).where(Poll.id == poll_id)
    )
    poll = result.scalar_one_or_none()

    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")

    await _verify_poll_access(db, poll, user.id)  # КАО#006: IDOR fix

    return build_poll_response(poll, poll.votes, user.id)


@router.post("/{poll_id}/vote", response_model=PollResponse)
async def vote_poll(
    poll_id: str,
    data: PollVoteRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Vote on a poll (or change vote)."""
    result = await db.execute(
        select(Poll).options(selectinload(Poll.votes)).where(Poll.id == poll_id)
    )
    poll = result.scalar_one_or_none()

    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")

    await _verify_poll_access(db, poll, user.id)  # КАО#006: IDOR fix (block non-participant voting/reading)

    # Check if poll is closed or expired
    if poll.is_closed:
        raise HTTPException(status_code=400, detail="Poll is closed")
    
    if poll.expires_at and datetime.utcnow() > poll.expires_at:
        raise HTTPException(status_code=400, detail="Poll has expired")
    
    # Validate selected options
    for opt_idx in data.selected_options:
        if opt_idx < 0 or opt_idx >= len(poll.options):
            raise HTTPException(status_code=400, detail=f"Invalid option index: {opt_idx}")
    
    # Check multiple choice
    if not poll.is_multiple and len(data.selected_options) > 1:
        raise HTTPException(status_code=400, detail="This poll allows only one selection")

    # КАО#295: de-duplicate. A multi-choice ballot like [1,1,1] was stored verbatim and build_poll_response
    # counts every occurrence, so one voter could inflate an option's tally and push percentages past 100%.
    data.selected_options = sorted(set(data.selected_options))
    
    # КАО#251 (#24): UPDATE the existing vote in place instead of delete+insert — with the new
    # unique(poll_id,user_id) constraint a delete+insert of the same key collides on flush ordering.
    existing_vote = next((v for v in poll.votes if v.user_id == user.id), None)
    if existing_vote:
        existing_vote.selected_options = data.selected_options
    else:
        db.add(PollVote(
            id=str(uuid4()),
            poll_id=poll_id,
            user_id=user.id,
            selected_options=data.selected_options
        ))
    try:
        await db.commit()
    except IntegrityError:
        # Concurrent first-vote by the same user hit the unique constraint — tally stays correct.
        await db.rollback()

    # Re-fetch with votes (authoritative after either the committed or the rolled-back path).
    # КАО#251 Round-2: populate_existing forces the identity-mapped Poll (+ its votes collection) to
    # RELOAD from the DB — without it the just-added vote isn't reflected and the /vote RESPONSE
    # returns a stale total of 0 (the persisted data is correct, but the client showed 0 until refresh).
    result = await db.execute(
        select(Poll).options(selectinload(Poll.votes)).where(Poll.id == poll_id).execution_options(populate_existing=True)
    )
    poll = result.scalar_one_or_none()  # КАО#251 R3: tolerate a concurrent delete (was scalar_one → 500)
    if poll is None:
        raise HTTPException(status_code=404, detail="Poll not found")

    response = build_poll_response(poll, poll.votes, user.id)
    
    # Get member_ids before closing session
    notify_user_ids = []
    if poll.creator_id != user.id:
        notify_user_ids.append(poll.creator_id)
    if poll.group_id:
        from app.models.group import GroupMember
        members_result = await db.execute(
            select(GroupMember.user_id).where(GroupMember.group_id == poll.group_id)
        )
        for m in members_result.fetchall():
            if m[0] != user.id and m[0] not in notify_user_ids:
                notify_user_ids.append(m[0])
    elif poll.chat_id and poll.chat_id != user.id:
        notify_user_ids.append(poll.chat_id)
    
    # КАО#243 (#10): per-recipient payload (user_voted/user_selections are personal). Serialize NOW
    # (session open, ORM objects live) — the detached task must not touch the ORM (objects are expired
    # after commit → lazy IO there raises MissingGreenlet).
    per_payloads = {uid: build_poll_response(poll, poll.votes, uid).model_dump(mode='json') for uid in notify_user_ids}

    async def notify_poll_update():
        for uid, pd in per_payloads.items():
            await ws_manager.send_to_user(
                uid,
                WSMessage(type=WSMessageType.POLL_UPDATE, payload={"poll_id": poll_id, "poll": pd})
            )

    asyncio.create_task(notify_poll_update())
    return response


@router.post("/{poll_id}/close", response_model=PollResponse)
async def close_poll(
    poll_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Close a poll (only creator can close)."""
    result = await db.execute(
        select(Poll).options(selectinload(Poll.votes)).where(Poll.id == poll_id)
    )
    poll = result.scalar_one_or_none()
    
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if poll.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Only poll creator can close it")
    
    poll.is_closed = True
    await db.commit()
    await db.refresh(poll)
    
    return build_poll_response(poll, poll.votes, user.id)


@router.delete("/{poll_id}/vote")
async def remove_vote(
    poll_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Remove user's vote from a poll."""
    result = await db.execute(
        select(Poll).where(Poll.id == poll_id)
    )
    poll = result.scalar_one_or_none()

    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")

    await _verify_poll_access(db, poll, user.id)  # КАО#006: IDOR fix

    if poll.is_closed:
        raise HTTPException(status_code=400, detail="Poll is closed")
    
    # Find and delete vote
    result = await db.execute(
        select(PollVote).where(
            and_(PollVote.poll_id == poll_id, PollVote.user_id == user.id)
        )
    )
    vote = result.scalar_one_or_none()
    
    if vote:
        await db.delete(vote)
        await db.commit()
    
        
        # Reload poll and broadcast update (КАО#251 Round-2: populate_existing so the removed vote is
        # reflected — otherwise the identity-mapped votes collection stays stale).
        result = await db.execute(
            select(Poll).options(selectinload(Poll.votes)).where(Poll.id == poll_id).execution_options(populate_existing=True)
        )
        poll = result.scalar_one_or_none()  # КАО#251 R3: tolerate concurrent delete
        if poll is None:
            return {"status": "ok"}
        response = build_poll_response(poll, poll.votes, user.id)
        
        # Get users to notify
        notify_user_ids = []
        if poll.creator_id != user.id:
            notify_user_ids.append(poll.creator_id)
        if poll.group_id:
            from app.models.group import GroupMember
            members_result = await db.execute(
                select(GroupMember.user_id).where(GroupMember.group_id == poll.group_id)
            )
            for m in members_result.fetchall():
                if m[0] != user.id and m[0] not in notify_user_ids:
                    notify_user_ids.append(m[0])
        elif poll.chat_id and poll.chat_id != user.id:
            notify_user_ids.append(poll.chat_id)
        
        # Broadcast — КАО#243 (#10): per-recipient payload, serialized NOW (detached task must not
        # touch expired ORM objects → MissingGreenlet).
        per_payloads = {uid: build_poll_response(poll, poll.votes, uid).model_dump(mode='json') for uid in notify_user_ids}

        async def notify_retract():
            for uid, pd in per_payloads.items():
                await ws_manager.send_to_user(
                    uid,
                    WSMessage(type=WSMessageType.POLL_UPDATE, payload={"poll_id": poll_id, "poll": pd})
                )

        asyncio.create_task(notify_retract())
    return {"status": "ok"}


@router.put("/{poll_id}/message")
async def link_poll_to_message(
    poll_id: str,
    message_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Link poll to a message (called after message is sent)."""
    result = await db.execute(
        select(Poll).where(Poll.id == poll_id)
    )
    poll = result.scalar_one_or_none()
    
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if poll.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Only creator can link poll")
    
    poll.message_id = message_id
    await db.commit()
    
    return {"status": "ok", "poll_id": poll_id, "message_id": message_id}
