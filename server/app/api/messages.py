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
Message API endpoints.
"""
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, update, delete, func, text  # КАО#322: advisory lock for the pin limit
from sqlalchemy.exc import IntegrityError  # КАО#050

from app.database import get_db
from app.models.message import (
    Message, MessageType, MessageStatus, PinnedMessage, MessageReaction,
    MessageSend, MessageResponse, MessageAck, MessageEdit, MessagesQuery,
    WSMessage, WSMessageType, ReactionRequest, ReactionSummary, ReactionsResponse,
    ReactionUserInfo,
)
from app.models.user import User
from app.models.group import GroupMember, Group
from app.api.auth import get_current_user_id, get_current_user
from app.services.websocket_manager import ws_manager
from app.rate_limiter import user_limiter, RATE_LIMIT_SEND


router = APIRouter(prefix="/messages", tags=["Messages"])


@router.post("/send", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
@user_limiter.limit(RATE_LIMIT_SEND)
async def send_message(
    request: Request,
    message: MessageSend,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Send an encrypted message.
    
    The server stores the encrypted payload without ability to decrypt.
    Message is delivered via WebSocket if recipient is online,
    otherwise stored for later retrieval.
    
    For group messages, set group_id. For direct messages, set recipient_id.
    """
    from app.models.group import Group, GroupMember
    
    # Must have either recipient_id or group_id
    if not message.recipient_id and not message.group_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either recipient_id or group_id is required"
        )
    
    # Handle group message
    if message.group_id:
        # Verify user is a member
        member_check = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == message.group_id,
                    GroupMember.user_id == user_id,
                )
            )
        )
        if not member_check.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this group"
            )
        
        # Get group for name
        group_result = await db.execute(select(Group).where(Group.id == message.group_id))
        group = group_result.scalar_one_or_none()
        if not group or group.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Group not found"
            )

        # v3.11.10: Channel posting restriction
        # Subscribers can only comment (reply_to_id), not create top-level posts
        if hasattr(group, 'is_channel') and group.is_channel:
            member_result = await db.execute(
                select(GroupMember).where(
                    and_(
                        GroupMember.group_id == message.group_id,
                        GroupMember.user_id == user_id,
                    )
                )
            )
            member_obj = member_result.scalar_one_or_none()
            if member_obj and member_obj.role not in ("owner", "admin"):
                if not message.reply_to_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Only channel admins can create posts. Use reply to comment."
                    )
    else:
        # Verify recipient exists (direct message)
        result = await db.execute(
            select(User).where(User.id == message.recipient_id)
        )
        recipient = result.scalar_one_or_none()
        
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found"
            )
        
        # v3.6.0: Check if sender is blocked by recipient
        try:
            from app.api.user_settings import UserBlock
            block_check = await db.execute(
                select(UserBlock).where(
                    and_(
                        UserBlock.blocker_id == message.recipient_id,
                        UserBlock.blocked_id == user_id
                    )
                )
            )
            if block_check.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You cannot send messages to this user"
                )
        except ImportError:
            pass  # UserBlock not available, skip check
    
    # Get sender and check permissions
    sender_result = await db.execute(select(User).where(User.id == user_id))
    sender = sender_result.scalar_one_or_none()
    
    if sender:
        if message.message_type == MessageType.TEXT and not sender.can_send_text:
            raise HTTPException(status_code=403, detail="You are not allowed to send text messages")
        if message.message_type == MessageType.FILE and not sender.can_send_files:
            raise HTTPException(status_code=403, detail="You are not allowed to send files")
        if message.message_type == MessageType.VOICE and not sender.can_send_voice:
            raise HTTPException(status_code=403, detail="You are not allowed to send voice messages")
    
    # Check for duplicate (idempotency)
    if message.client_message_id:
        result = await db.execute(
            select(Message).where(
                and_(
                    Message.sender_id == user_id,
                    Message.client_message_id == message.client_message_id,
                )
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return MessageResponse.model_validate(existing)
    
    # Calculate expiration
    expires_at = None
    if message.expires_in_seconds:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=message.expires_in_seconds)
    
    # Create message
    import json
    mentions_json = None
    if message.mentions:
        mentions_json = json.dumps(message.mentions)
    
    db_message = Message(
        sender_id=user_id,
        recipient_id=message.recipient_id,
        group_id=message.group_id,
        message_type=message.message_type,
        encrypted_payload=message.encrypted_payload,
        file_id=message.file_id,
        client_message_id=message.client_message_id,
        expires_at=expires_at,
        forwarded_from_id=message.forwarded_from_id,
        forwarded_from_name=message.forwarded_from_name,
        reply_to_id=message.reply_to_id,
        mentions=mentions_json,
        encrypted_for_self=message.encrypted_for_self,
    )
    
    db.add(db_message)
    await db.flush()
    
    # Get sender name for notifications and group messages
    sender_name = None
    if sender:
        sender_name = sender.display_name or sender.username
    
    response = MessageResponse(
        id=db_message.id,
        sender_id=db_message.sender_id,
        recipient_id=db_message.recipient_id,
        group_id=db_message.group_id,
        message_type=db_message.message_type,
        encrypted_payload=db_message.encrypted_payload,
        file_id=db_message.file_id,
        status=db_message.status,
        client_message_id=db_message.client_message_id,
        created_at=db_message.created_at,
        delivered_at=db_message.delivered_at,
        expires_at=db_message.expires_at,
        edited_at=db_message.edited_at,
        forwarded_from_id=db_message.forwarded_from_id,
        forwarded_from_name=db_message.forwarded_from_name,
        reply_to_id=db_message.reply_to_id,
        mentions=message.mentions,
        encrypted_for_self=db_message.encrypted_for_self,
        sender_name=sender_name,
        sender_key_distribution=message.sender_key_distribution,  # Group E2EE
    )
    
    # For group messages, get member IDs before commit
    member_ids_to_notify = []
    group_name = None
    if message.group_id:
        members_result = await db.execute(
            select(GroupMember).where(GroupMember.group_id == message.group_id)
        )
        members = members_result.scalars().all()
        member_ids_to_notify = [m.user_id for m in members if m.user_id != user_id]
        # Get group name for push notifications
        group_result = await db.execute(select(Group).where(Group.id == message.group_id))
        group_obj = group_result.scalar_one_or_none()
        if group_obj:
            group_name = group_obj.name
    
    # Mark file as attached (if any)
    if message.file_id:
        from app.api.files import mark_file_attached
        # КАО#007 + Round-2 fix: enforce ownership for normal sends, but allow forwards, which legitimately
        # re-reference the original uploader's file_id (file bytes are E2EE/at-rest, so re-attach is low-risk).
        _owner = None if message.forwarded_from_id else user_id
        await mark_file_attached(db, message.file_id, db_message.id, owner_id=_owner)
    
    # Commit message to DB before WebSocket notifications
    await db.commit()
    
    # Send WebSocket notifications in background (don't block response)
    import asyncio
    from app.services.push_service import push_service
    from app.models.user import PushSubscription
    from app.database import async_session_maker
    
    async def notify_recipients():
        try:
            if message.group_id:
                # Send WebSocket to all group members except sender
                for member_id in member_ids_to_notify:
                    await ws_manager.send_to_user(
                        member_id,
                        WSMessage(
                            type=WSMessageType.NEW_MESSAGE,
                            payload=response.model_dump(mode="json"),
                        )
                    )
                
                # Send push ONLY to mentioned users (ignore mute)
                mentioned_user_ids = set()
                if message.mentions:
                    if "@all" in message.mentions:
                        # @all - notify everyone
                        mentioned_user_ids = set(member_ids_to_notify)
                    else:
                        # Only specific users
                        mentioned_user_ids = set(message.mentions) & set(member_ids_to_notify)
                
                for mentioned_id in mentioned_user_ids:
                    # For group mentions, chat_id is 'group_' + group_id
                    group_chat_id = 'group_' + message.group_id
                    await send_push_to_user(mentioned_id, sender_name or "New message", 
                                          "You were mentioned", group_name, group_chat_id)
            else:
                # Direct message - send via WebSocket
                await ws_manager.send_to_user(
                    message.recipient_id,
                    WSMessage(
                        type=WSMessageType.NEW_MESSAGE,
                        payload=response.model_dump(mode="json"),
                    )
                )
                # Always send push (SW will decide to show or not based on focus)
                # For direct messages, chat_id is the sender's user_id
                await send_push_to_user(message.recipient_id, 
                                      sender_name or "New message", 
                                      "New message", None, user_id)
            
            # Notify sender about message status (includes full message for multi-device sync)
            await ws_manager.send_to_user(
                user_id,
                WSMessage(
                    type=WSMessageType.MESSAGE_SENT,
                    payload={
                        "message_id": db_message.id,
                        "client_message_id": message.client_message_id,
                        "status": db_message.status.value,
                        "message": response.model_dump(mode="json"),  # v3.7.1: Full message for other devices
                    }
                ),
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"WebSocket notification error: {e}")
    
    async def send_push_to_user(target_user_id: str, sender_name: str, preview: str, group_name: str | None, chat_id: str | None = None):
        """Send push notification to user and cleanup invalid subscriptions."""
        try:
            async with async_session_maker() as push_db:
                # v3.6.0: Check if chat is muted by recipient
                if chat_id:
                    try:
                        from app.api.user_settings import MutedChat
                        from datetime import datetime, timezone
                        
                        mute_check = await push_db.execute(
                            select(MutedChat).where(
                                and_(
                                    MutedChat.user_id == target_user_id,
                                    MutedChat.chat_id == chat_id
                                )
                            )
                        )
                        muted_chat = mute_check.scalar_one_or_none()
                        
                        if muted_chat:
                            # Check if mute is still active
                            if muted_chat.muted_until is None or muted_chat.muted_until > datetime.now(timezone.utc):
                                import logging
                                logging.getLogger(__name__).info(f"Skipping push for {target_user_id} - chat {chat_id} is muted")
                                return  # Don't send push
                    except ImportError:
                        pass  # MutedChat not available
                
                result = await push_db.execute(
                    select(PushSubscription).where(PushSubscription.user_id == target_user_id)
                )
                subscriptions = result.scalars().all()
                
                subscriptions_to_remove = []
                
                for sub in subscriptions:
                    subscription_info = {
                        "endpoint": sub.endpoint,
                        "keys": {
                            "p256dh": sub.p256dh,
                            "auth": sub.auth
                        }
                    }
                    if group_name:
                        push_result = push_service.send_group_message_notification(
                            subscription_info, sender_name, group_name, preview
                        )
                    else:
                        push_result = push_service.send_message_notification(
                            subscription_info, sender_name, preview
                        )
                    
                    # Mark invalid subscriptions for removal
                    if push_result.should_remove:
                        subscriptions_to_remove.append(sub.id)
                        import logging
                        logging.getLogger(__name__).info(f"Marking subscription {sub.id} for removal (invalid)")
                    elif push_result.success:
                        import logging
                        logging.getLogger(__name__).info(f"Push notification sent to {target_user_id}")
                
                # Remove invalid subscriptions from DB
                if subscriptions_to_remove:
                    await push_db.execute(
                        delete(PushSubscription).where(PushSubscription.id.in_(subscriptions_to_remove))
                    )
                    await push_db.commit()
                    import logging
                    logging.getLogger(__name__).info(f"Removed {len(subscriptions_to_remove)} invalid push subscriptions")
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Failed to send push: {e}")
    
    # Fire and forget
    asyncio.create_task(notify_recipients())
    
    return response


@router.get("/pending", response_model=list[MessageResponse])
async def get_pending_messages(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Fetch pending messages for current user.
    
    Returns messages that haven't been delivered yet.
    Client should call /ack after processing.
    """
    result = await db.execute(
        select(Message)
        .where(
            and_(
                Message.recipient_id == user_id,
                Message.status == MessageStatus.PENDING,
                # КАО#318: skip messages already deleted for this recipient. delete_message(for_everyone)
                # only sets the flags — the row stays PENDING — so an undelivered retracted message was
                # handed straight back to the client on the next /pending poll, undoing the retraction
                # (and re-inserting it into the chat). Mirrors the КАО#292 / history filters.
                Message.deleted_for_recipient == False,
                or_(
                    Message.expires_at.is_(None),
                    Message.expires_at > datetime.now(timezone.utc),
                )
            )
        )
        .order_by(Message.created_at.asc())
        .limit(limit)
    )
    
    messages = result.scalars().all()
    return [MessageResponse.model_validate(m) for m in messages]


@router.get("/conversations")
async def get_conversations(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get all conversations (contacts) for the current user.
    
    Returns unique contacts with their last message.
    This is used to sync chats across devices.
    """
    from sqlalchemy import func, case, literal_column
    
    since = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Build the contact_id expression
    contact_id_expr = case(
        (Message.sender_id == user_id, Message.recipient_id),
        else_=Message.sender_id
    ).label('contact_id')
    
    # Get all unique contacts from messages (sent or received)
    # Direct messages only (group_id is NULL)
    try:
        result = await db.execute(
            select(
                contact_id_expr,
                func.max(Message.created_at).label('last_message_at'),
            )
            .where(
                and_(
                    or_(
                        Message.sender_id == user_id,
                        Message.recipient_id == user_id,
                    ),
                    Message.group_id.is_(None),
                    Message.created_at >= since,
                )
            )
            .group_by(literal_column('contact_id'))
        )
        
        contacts = result.all()
    except Exception as e:
        # Fallback: simpler query without aggregation
        result = await db.execute(
            select(Message.sender_id, Message.recipient_id, Message.created_at)
            .where(
                and_(
                    or_(
                        Message.sender_id == user_id,
                        Message.recipient_id == user_id,
                    ),
                    Message.group_id.is_(None),
                    Message.created_at >= since,
                )
            )
            .order_by(Message.created_at.desc())
        )
        
        # Manually extract unique contacts
        seen = set()
        contacts = []
        for row in result.all():
            contact = row.recipient_id if row.sender_id == user_id else row.sender_id
            if contact and contact not in seen and contact != user_id:
                seen.add(contact)
                contacts.append((contact, row.created_at))
    
    # Get user info for each contact
    conversations = []
    for item in contacts:
        contact_id = item[0]
        last_message_at = item[1] if len(item) > 1 else None
        
        if not contact_id or contact_id == user_id:
            continue
            
        user_result = await db.execute(
            select(User).where(User.id == contact_id)
        )
        user = user_result.scalar_one_or_none()
        
        if user:
            # Get the last message
            # КАО#292: exclude messages soft-deleted FOR THIS USER, mirroring get_message_history.
            # Without this, delete_message(for_everyone=True) — which only sets both deleted_for_* flags
            # and never removes the row — left the retracted ciphertext as this conversation's preview,
            # defeating "delete for everyone"; likewise a "delete for me" message stayed in the chat list.
            last_msg_result = await db.execute(
                select(Message)
                .where(
                    and_(
                        or_(
                            and_(Message.sender_id == user_id, Message.recipient_id == contact_id),
                            and_(Message.sender_id == contact_id, Message.recipient_id == user_id),
                        ),
                        Message.group_id.is_(None),
                        or_(
                            and_(Message.sender_id == user_id, Message.deleted_for_sender == False),
                            and_(Message.recipient_id == user_id, Message.deleted_for_recipient == False),
                        ),
                    )
                )
                .order_by(Message.created_at.desc())
                .limit(1)
            )
            last_msg = last_msg_result.scalar_one_or_none()
            
            conversations.append({
                "contact_id": contact_id,
                "username": user.username,
                "display_name": user.display_name or user.username,
                "avatar_url": user.avatar_url,
                "last_message_at": last_message_at.isoformat() if last_message_at else None,
                "last_message": MessageResponse.model_validate(last_msg).model_dump() if last_msg else None,
            })
    
    return conversations


@router.post("/ack", status_code=status.HTTP_204_NO_CONTENT)
async def acknowledge_messages(
    ack: MessageAck,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Acknowledge message receipt or read status.
    
    Updates message status and notifies sender.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"ACK received: user={user_id}, status={ack.status}, messages={ack.message_ids}")
    
    result = await db.execute(
        select(Message).where(
            and_(
                Message.id.in_(ack.message_ids),
                Message.recipient_id == user_id,
            )
        )
    )
    
    messages = result.scalars().all()
    now = datetime.now(timezone.utc)
    
    logger.info(f"Found {len(messages)} messages to update")
    
    for msg in messages:
        old_status = msg.status
        if ack.status == MessageStatus.DELIVERED:
            if msg.status == MessageStatus.PENDING:
                msg.status = MessageStatus.DELIVERED
                msg.delivered_at = now
        elif ack.status == MessageStatus.READ:
            msg.status = MessageStatus.READ
            msg.read_at = now
        
        logger.info(f"Message {msg.id}: {old_status} -> {msg.status}, notifying sender {msg.sender_id}")
        
        # Notify sender
        await ws_manager.send_to_user(
            msg.sender_id,
            WSMessage(
                type=WSMessageType.MESSAGE_STATUS,
                payload={
                    "message_id": msg.id,
                    "status": msg.status.value,
                    "timestamp": now.isoformat(),
                }
            )
        )
    
    # КАО#210 (group read receipts): DMs use recipient_id (handled above); group messages had no handling
    # (silent no-op). Notify the sender that this member read it (per-member, ephemeral via WS; full
    # per-member persistence would need a dedicated read-state table).
    # КАО#210 Round-3: membership resolved in a SINGLE query (was one GroupMember SELECT per message →
    # N+1/DoS amplification); message_ids is also capped at the model level.
    if ack.status == MessageStatus.READ and ack.message_ids:
        from app.models.group import GroupMember
        grp_msgs = (await db.execute(
            select(Message).where(
                and_(Message.id.in_(ack.message_ids), Message.group_id.isnot(None), Message.sender_id != user_id)
            )
        )).scalars().all()
        if grp_msgs:
            group_ids = {gm.group_id for gm in grp_msgs}
            member_of = set((await db.execute(
                select(GroupMember.group_id).where(
                    and_(GroupMember.group_id.in_(group_ids), GroupMember.user_id == user_id)
                )
            )).scalars().all())
            for gmsg in grp_msgs:
                if gmsg.group_id in member_of:
                    await ws_manager.send_to_user(
                        gmsg.sender_id,
                        WSMessage(
                            type=WSMessageType.MESSAGE_STATUS,
                            payload={"message_id": gmsg.id, "status": "read", "reader_id": user_id, "group_id": gmsg.group_id, "timestamp": now.isoformat()}
                        )
                    )

    # Commit changes to database
    await db.commit()


@router.get("/history/{contact_id}")
async def get_message_history(
    contact_id: str,
    before_id: str | None = None,
    after_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get message history with a specific contact.
    
    Supports cursor-based pagination using before_id/after_id.
    Excludes messages deleted for current user.
    Includes reactions for each message.
    """
    # Base query: messages between user and contact, excluding deleted ones
    query = select(Message).where(
        and_(
            or_(
                and_(Message.sender_id == user_id, Message.recipient_id == contact_id),
                and_(Message.sender_id == contact_id, Message.recipient_id == user_id),
            ),
            # Exclude messages deleted for current user
            or_(
                and_(Message.sender_id == user_id, Message.deleted_for_sender == False),
                and_(Message.recipient_id == user_id, Message.deleted_for_recipient == False),
            )
        )
    )
    
    if before_id:
        # Get messages before cursor
        result = await db.execute(select(Message).where(Message.id == before_id))
        cursor_msg = result.scalar_one_or_none()
        if cursor_msg:
            query = query.where(Message.created_at < cursor_msg.created_at)
        query = query.order_by(Message.created_at.desc())
    elif after_id:
        # Get messages after cursor
        result = await db.execute(select(Message).where(Message.id == after_id))
        cursor_msg = result.scalar_one_or_none()
        if cursor_msg:
            query = query.where(Message.created_at > cursor_msg.created_at)
        query = query.order_by(Message.created_at.asc())
    else:
        # Get latest messages
        query = query.order_by(Message.created_at.desc())
    
    result = await db.execute(query.limit(limit))
    messages = result.scalars().all()
    
    # Reverse if we fetched in desc order
    if not after_id:
        messages = list(reversed(messages))
    
    # Get reactions for all messages
    message_ids = [m.id for m in messages]
    reactions_map = {}
    
    if message_ids:
        reactions_result = await db.execute(
            select(MessageReaction, User.display_name)
            .join(User, MessageReaction.user_id == User.id)
            .where(MessageReaction.message_id.in_(message_ids))
        )
        reactions_data = reactions_result.fetchall()
        
        # Group reactions by message
        for reaction, display_name in reactions_data:
            if reaction.message_id not in reactions_map:
                reactions_map[reaction.message_id] = {}
            emoji = reaction.emoji
            if emoji not in reactions_map[reaction.message_id]:
                reactions_map[reaction.message_id][emoji] = []
            reactions_map[reaction.message_id][emoji].append({
                "user_id": reaction.user_id,
                "display_name": display_name
            })
    
    # Build response with reactions
    response = []
    for m in messages:
        msg_data = MessageResponse.model_validate(m).model_dump()
        
        # Parse mentions from JSON
        if m.mentions:
            try:
                msg_data["mentions"] = json.loads(m.mentions)
            except:
                msg_data["mentions"] = None
        
        # Add reactions
        msg_reactions = []
        if m.id in reactions_map:
            for emoji, users in reactions_map[m.id].items():
                msg_reactions.append({
                    "emoji": emoji,
                    "count": len(users),
                    "users": users
                })
        msg_data["reactions"] = msg_reactions
        response.append(msg_data)
    
    return response


@router.delete("/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_message(
    message_id: str,
    for_everyone: bool = Query(default=False, description="Delete for all participants"),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Delete a message.
    
    - for_everyone=False: Delete only for current user (soft delete)
    - for_everyone=True: Delete for all participants (sender only)
    """
    result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Check if user is participant
    is_participant = False
    
    if message.group_id:
        # Group message - check if user is member of the group
        from app.models.group import GroupMember
        member_result = await db.execute(
            select(GroupMember).where(
                and_(GroupMember.group_id == message.group_id, GroupMember.user_id == user_id)
            )
        )
        is_participant = member_result.scalar_one_or_none() is not None
    else:
        # Direct message - check if user is sender or recipient
        is_participant = (message.sender_id == user_id or message.recipient_id == user_id)
    
    if not is_participant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this message"
        )
    
    if for_everyone:
        # Only sender can delete for everyone
        if message.sender_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only sender can delete for everyone"
            )
        
        # Mark as deleted for both
        message.deleted_for_sender = True
        message.deleted_for_recipient = True

        # КАО#368: a retracted message must release its pin slot. Deletion is soft, so the PinnedMessage row
        # survived; since КАО#335 the pinned LIST filters the message out, but the max-5 check in pin_message
        # counts PinnedMessage rows unconditionally. The slot was therefore consumed by a pin the UI can
        # neither display nor unpin. Measured on stage: pinned list shows 4 while pinning returns
        # 400 "Maximum 5 pinned messages reached" — with five retracted pins the chat can never be pinned in
        # again. Only in the for_everyone branch: doing it for a personal delete would unpin for everybody.
        await db.execute(delete(PinnedMessage).where(PinnedMessage.message_id == message_id))
        message.is_pinned = False

        # Prepare notification
        delete_msg = WSMessage(
            type=WSMessageType.MESSAGE_DELETED,
            payload={
                "message_id": message_id,
                "deleted_by": user_id,
                "for_everyone": True,
            }
        )
        
        # Notify based on message type (group or direct)
        if message.group_id:
            # Group message - notify all members
            from app.models.group import GroupMember
            members_result = await db.execute(
                select(GroupMember.user_id).where(GroupMember.group_id == message.group_id)
            )
            for m in members_result.fetchall():
                await ws_manager.send_to_user(m[0], delete_msg)
        else:
            # Direct message - notify recipient and sender
            if message.recipient_id:
                await ws_manager.send_to_user(message.recipient_id, delete_msg)
            await ws_manager.send_to_user(user_id, delete_msg)
    else:
        # Delete only for current user
        if message.group_id:
            # Group message - use MessageUserDeletion table
            if message.sender_id == user_id:
                message.deleted_for_sender = True
            else:
                # For non-senders in groups: add to user deletions table
                from app.models.message import MessageUserDeletion
                # КАО#051: make 'delete for me' idempotent (avoid duplicate-row IntegrityError 500)
                _existing_del = await db.execute(
                    select(MessageUserDeletion).where(
                        and_(
                            MessageUserDeletion.message_id == message_id,
                            MessageUserDeletion.user_id == user_id,
                        )
                    )
                )
                if not _existing_del.scalar_one_or_none():
                    deletion = MessageUserDeletion(
                        message_id=message_id,
                        user_id=user_id
                    )
                    db.add(deletion)
        else:
            # Direct message
            if message.sender_id == user_id:
                message.deleted_for_sender = True
            else:
                message.deleted_for_recipient = True
        
        # Notify current user's other devices
        await ws_manager.send_to_user(
            user_id,
            WSMessage(
                type=WSMessageType.MESSAGE_DELETED,
                payload={
                    "message_id": message_id,
                    "deleted_by": user_id,
                    "for_everyone": False,
                }
            )
        )
    
    await db.commit()


@router.put("/{message_id}", response_model=MessageResponse)
async def edit_message(
    message_id: str,
    edit: MessageEdit,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Edit a message (sender only).
    
    Updates the encrypted payload and marks message as edited.
    """
    result = await db.execute(
        select(Message).where(
            and_(
                Message.id == message_id,
                Message.sender_id == user_id,
                Message.deleted_for_sender == False,
            )
        )
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found or not authorized"
        )
    
    # Only text messages can be edited
    if message.message_type != MessageType.TEXT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only text messages can be edited"
        )
    
    # Update message
    message.encrypted_payload = edit.encrypted_payload
    if edit.encrypted_for_self:
        message.encrypted_for_self = edit.encrypted_for_self
    message.edited_at = datetime.now(timezone.utc)
    
    await db.flush()
    
    response = MessageResponse.model_validate(message)
    
    # Build notification payload
    edit_notification = WSMessage(
        type=WSMessageType.MESSAGE_EDITED,
        payload={
            "message_id": message_id,
            "encrypted_payload": edit.encrypted_payload,
            "encrypted_for_self": message.encrypted_for_self,  # КАО#150 (SER#14): sender's other devices decrypt the self-copy
            "edited_at": message.edited_at.isoformat(),
        }
    )
    
    # Notify based on message type (group or direct)
    if message.group_id:
        # Group message - notify all members except sender
        members_result = await db.execute(
            select(GroupMember.user_id).where(GroupMember.group_id == message.group_id)
        )
        for m in members_result.fetchall():
            if m[0] != user_id:
                await ws_manager.send_to_user(m[0], edit_notification)
    elif message.recipient_id and not message.deleted_for_recipient:
        # Direct message - notify recipient
        await ws_manager.send_to_user(message.recipient_id, edit_notification)
    
    # Notify sender's other devices
    await ws_manager.send_to_user(user_id, edit_notification)
    
    await db.commit()
    
    return response


@router.post("/typing/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def send_typing_indicator(
    contact_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Send typing indicator to contact.

    Delivered via WebSocket only, not stored.
    КАО#245 (#25): only deliver to an actual contact — a prior DM in either direction OR a shared
    group. Previously any user could push a forged "X is typing" event to any other user / probe presence.
    """
    if contact_id == user_id:
        return
    dm = await db.execute(
        select(Message.id).where(
            or_(
                and_(Message.sender_id == user_id, Message.recipient_id == contact_id),
                and_(Message.sender_id == contact_id, Message.recipient_id == user_id),
            )
        ).limit(1)
    )
    related = dm.scalar_one_or_none() is not None
    if not related:
        shared = await db.execute(
            select(GroupMember.group_id).where(
                and_(
                    GroupMember.user_id == user_id,
                    GroupMember.group_id.in_(
                        select(GroupMember.group_id).where(GroupMember.user_id == contact_id)
                    ),
                )
            ).limit(1)
        )
        related = shared.scalar_one_or_none() is not None
    if not related:
        return  # no relationship → silently drop (204)

    await ws_manager.send_to_user(
        contact_id,
        WSMessage(
            type=WSMessageType.USER_TYPING,
            payload={"user_id": user_id}
        )
    )


@router.post("/{message_id}/pin", status_code=status.HTTP_200_OK)
async def pin_message(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Pin a message in a chat. Up to 5 messages can be pinned per chat.
    
    Permissions:
    - Groups: only group creator can pin
    - Direct chats: both participants can pin
    """
    # Get the message
    result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Check permissions
    if message.group_id:
        # Group chat - only creator can pin
        group_result = await db.execute(
            select(Group).where(Group.id == message.group_id)
        )
        group = group_result.scalar_one_or_none()
        if not group or group.created_by != user_id:
            raise HTTPException(status_code=403, detail="Only group creator can pin messages")
        chat_id = message.group_id
    else:
        # Direct chat - both participants can pin
        if message.sender_id != user_id and message.recipient_id != user_id:
            raise HTTPException(status_code=403, detail="Not authorized")
        # Create consistent chat_id for direct chats
        user_ids = sorted([message.sender_id, message.recipient_id])
        chat_id = f"{user_ids[0]}_{user_ids[1]}"
    
    # КАО#322: serialise concurrent pins for THIS chat. uq_pinned_chat_message (КАО#299) only stops the
    # same message being pinned twice — it says nothing about the max-5-per-chat rule, so two requests
    # pinning DIFFERENT messages could both read count==4 and both insert, leaving 6 pins. A
    # transaction-scoped advisory lock makes the count-then-insert atomic without a table lock.
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:chat_key))"), {"chat_key": chat_id})

    # Check if already pinned
    existing_pin = await db.execute(
        select(PinnedMessage).where(
            PinnedMessage.chat_id == chat_id,
            PinnedMessage.message_id == message_id
        )
    )
    if existing_pin.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Message already pinned")
    
    # Check pin limit (max 5)
    pin_count = await db.execute(
        select(func.count()).select_from(PinnedMessage).where(PinnedMessage.chat_id == chat_id)
    )
    if pin_count.scalar() >= 5:
        raise HTTPException(status_code=400, detail="Maximum 5 pinned messages reached")
    
    # Create pin
    pinned = PinnedMessage(
        chat_id=chat_id,
        message_id=message_id,
        pinned_by=user_id
    )
    db.add(pinned)
    message.is_pinned = True
    try:
        await db.commit()
    except IntegrityError:
        # КАО#299: a concurrent request pinned the same message first and hit uq_pinned_chat_message.
        # The pin exists either way, so report success instead of a 500 (idempotent, like КАО#050/#251).
        await db.rollback()
        return {"status": "pinned", "message_id": message_id}

    # Notify participants
    notification = WSMessage(
        type=WSMessageType.NEW_MESSAGE,
        payload={"type": "message_pinned", "message_id": message_id, "chat_id": chat_id}
    )
    
    if message.group_id:
        members_result = await db.execute(
            select(GroupMember).where(GroupMember.group_id == message.group_id)
        )
        members = members_result.scalars().all()
        for member in members:
            if member.user_id != user_id:
                await ws_manager.send_to_user(member.user_id, notification)
    else:
        other_id = message.recipient_id if message.sender_id == user_id else message.sender_id
        await ws_manager.send_to_user(other_id, notification)
    
    return {"status": "pinned", "message_id": message_id}


@router.post("/{message_id}/unpin", status_code=status.HTTP_200_OK)
async def unpin_message(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Unpin a message.
    
    Permissions:
    - Groups: only group creator can unpin
    - Direct chats: both participants can unpin
    """
    result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Check permissions
    if message.group_id:
        group_result = await db.execute(
            select(Group).where(Group.id == message.group_id)
        )
        group = group_result.scalar_one_or_none()
        if not group or group.created_by != user_id:
            raise HTTPException(status_code=403, detail="Only group creator can unpin messages")
        chat_id = message.group_id
    else:
        if message.sender_id != user_id and message.recipient_id != user_id:
            raise HTTPException(status_code=403, detail="Not authorized")
        user_ids = sorted([message.sender_id, message.recipient_id])
        chat_id = f"{user_ids[0]}_{user_ids[1]}"
    
    # Delete pin record
    await db.execute(
        delete(PinnedMessage).where(
            PinnedMessage.chat_id == chat_id,
            PinnedMessage.message_id == message_id
        )
    )
    message.is_pinned = False
    await db.commit()
    
    # Notify participants
    notification = WSMessage(
        type=WSMessageType.NEW_MESSAGE,
        payload={"type": "message_unpinned", "message_id": message_id, "chat_id": chat_id}
    )
    
    if message.group_id:
        members_result = await db.execute(
            select(GroupMember).where(GroupMember.group_id == message.group_id)
        )
        members = members_result.scalars().all()
        for member in members:
            if member.user_id != user_id:
                await ws_manager.send_to_user(member.user_id, notification)
    else:
        other_id = message.recipient_id if message.sender_id == user_id else message.sender_id
        await ws_manager.send_to_user(other_id, notification)
    
    return {"status": "unpinned", "message_id": message_id}


@router.get("/pinned/{chat_id}")
async def get_pinned_messages(
    chat_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get pinned messages for a chat.
    chat_id can be:
    - group_id for group chats
    - recipient_id for direct chats (will be normalized)
    """
    # Determine if this is a group chat and check membership
    is_group_chat = chat_id.startswith('group_') or (
        '_' not in chat_id and len(chat_id) == 36  # UUID format, could be group_id
    )
    
    # Normalize chat_id for direct chats
    if not chat_id.startswith('group_') and '_' not in chat_id:
        # Could be either direct chat recipient_id or group_id
        # Check if it's a group first
        group_result = await db.execute(
            select(Group).where(Group.id == chat_id)
        )
        group = group_result.scalar_one_or_none()
        
        if group:
            # It's a group - verify membership
            membership_result = await db.execute(
                select(GroupMember).where(
                    and_(
                        GroupMember.group_id == chat_id,
                        GroupMember.user_id == user_id
                    )
                )
            )
            if not membership_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not a member of this group"
                )
            normalized_chat_id = chat_id
        else:
            # Direct chat - create consistent chat_id
            user_ids = sorted([user_id, chat_id])
            normalized_chat_id = f"{user_ids[0]}_{user_ids[1]}"
    else:
        # Starts with 'group_' prefix
        group_id = chat_id.replace('group_', '') if chat_id.startswith('group_') else chat_id
        
        # Check group exists and user is a member
        group_result = await db.execute(
            select(Group).where(Group.id == group_id)
        )
        group = group_result.scalar_one_or_none()
        
        if group:
            # Verify membership
            membership_result = await db.execute(
                select(GroupMember).where(
                    and_(
                        GroupMember.group_id == group_id,
                        GroupMember.user_id == user_id
                    )
                )
            )
            if not membership_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not a member of this group"
                )
        elif '_' in chat_id:
            # КАО#345 (auth bypass): a chat_id that ALREADY contains '_' is a normalized direct-chat key
            # ("<uuidA>_<uuidB>"). It skipped the first branch (which only handles ids without '_'), landed
            # here, found no Group with that id, and then fell straight through to the query with NO
            # authorization check at all — so any authenticated user could read the pinned messages
            # (ciphertext + metadata) of a private conversation between two OTHER users just by asking for
            # their sorted id pair. Require the caller to be one of the two participants.
            if user_id not in chat_id.split('_'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not a participant of this chat"
                )
        else:
            # Neither an existing group nor a direct-chat key we can validate — refuse rather than serve.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for this chat"
            )

        normalized_chat_id = group_id
    
    # Get pinned message records
    result = await db.execute(
        select(PinnedMessage)
        .where(PinnedMessage.chat_id == normalized_chat_id)
        .order_by(PinnedMessage.pinned_at.desc())
    )
    pinned_records = result.scalars().all()
    
    if not pinned_records:
        return []
    
    # Get actual messages
    message_ids = [p.message_id for p in pinned_records]
    # КАО#335: a pinned message that was later deleted for everyone stayed fully readable through this
    # endpoint (ciphertext included) — pinning silently defeated retraction. Apply the same visibility
    # rules used by /history, get_group_messages and get_comments.
    from app.models.message import MessageUserDeletion
    _deleted_by_viewer = select(MessageUserDeletion.message_id).where(
        MessageUserDeletion.user_id == user_id
    ).scalar_subquery()
    messages_result = await db.execute(
        select(Message).where(
            Message.id.in_(message_ids),
            ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),
            ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),
            ~and_(Message.recipient_id == user_id, Message.deleted_for_recipient == True),
            ~Message.id.in_(_deleted_by_viewer),
        )
    )
    messages = {m.id: m for m in messages_result.scalars().all()}
    
    # Build response
    pinned_messages = []
    for pin in pinned_records:
        msg = messages.get(pin.message_id)
        if msg:
            pinned_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "encrypted_payload": msg.encrypted_payload,
                "created_at": msg.created_at.isoformat() if msg.created_at else None,
                "pinned_at": pin.pinned_at.isoformat() if pin.pinned_at else None,
                "pinned_by": pin.pinned_by,
            })
    
    return pinned_messages


# ============== REACTIONS ==============

# Allowed emoji for reactions
ALLOWED_REACTIONS = {'👍', '❤️', '😂', '😮', '😢', '🔥'}


@router.post("/{message_id}/react", status_code=status.HTTP_200_OK)
async def add_reaction(
    message_id: str,
    reaction: ReactionRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Add or update reaction to a message.
    If user already has a reaction, it will be replaced.
    If same emoji is sent again, reaction will be removed.
    """
    # Validate emoji
    if reaction.emoji not in ALLOWED_REACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid emoji. Allowed: {', '.join(ALLOWED_REACTIONS)}"
        )
    
    # Get message and verify access
    result = await db.execute(select(Message).where(Message.id == message_id))
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Check access: user must be sender, recipient, or group member
    has_access = False
    chat_user_ids = []
    
    if message.group_id:
        # Group message - check membership
        member_result = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == message.group_id,
                    GroupMember.user_id == user_id
                )
            )
        )
        if member_result.scalar_one_or_none():
            has_access = True
            # Get all group members for notification
            members_result = await db.execute(
                select(GroupMember.user_id).where(GroupMember.group_id == message.group_id)
            )
            chat_user_ids = [m[0] for m in members_result.fetchall()]
    else:
        # Direct message
        if user_id in [message.sender_id, message.recipient_id]:
            has_access = True
            chat_user_ids = [message.sender_id, message.recipient_id]
    
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Check for existing reaction
    existing_result = await db.execute(
        select(MessageReaction).where(
            and_(
                MessageReaction.message_id == message_id,
                MessageReaction.user_id == user_id
            )
        )
    )
    existing = existing_result.scalar_one_or_none()
    
    action = "added"
    
    if existing:
        if existing.emoji == reaction.emoji:
            # Same emoji - remove reaction
            await db.delete(existing)
            action = "removed"
        else:
            # Different emoji - update
            existing.emoji = reaction.emoji
            existing.created_at = datetime.now(timezone.utc)
            action = "updated"
    else:
        # New reaction
        new_reaction = MessageReaction(
            message_id=message_id,
            user_id=user_id,
            emoji=reaction.emoji
        )
        db.add(new_reaction)

    try:
        await db.commit()
    except IntegrityError:
        # КАО#050: concurrent reaction insert raced the unique constraint — treat as idempotent
        await db.rollback()

    # Get user display name for notification
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    user_display_name = user.display_name if user else "Unknown"
    
    # Get updated reactions summary
    reactions_summary = await _get_reactions_summary(db, message_id)
    
    # Broadcast to all chat participants via WebSocket
    ws_payload = {
        "message_id": message_id,
        "user_id": user_id,
        "user_name": user_display_name,
        "emoji": reaction.emoji if action != "removed" else None,
        "action": action,
        "reactions": [r.model_dump() for r in reactions_summary],
        "group_id": message.group_id,
        "chat_id": message.recipient_id if not message.group_id else None,
    }
    
    ws_message = WSMessage(
        type=WSMessageType.MESSAGE_REACTION,
        payload=ws_payload
    )
    
    # КАО#052: fan out WS notifications in the background (was sequential awaits blocking the request)
    import asyncio
    async def _reaction_fanout():
        for uid in chat_user_ids:
            if uid:
                await ws_manager.send_to_user(uid, ws_message)
    asyncio.create_task(_reaction_fanout())
    
    return {
        "action": action,
        "message_id": message_id,
        "emoji": reaction.emoji if action != "removed" else None,
        "reactions": [r.model_dump() for r in reactions_summary]
    }


@router.delete("/{message_id}/react", status_code=status.HTTP_200_OK)
async def remove_reaction(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Remove user's reaction from a message."""
    # Get existing reaction
    result = await db.execute(
        select(MessageReaction).where(
            and_(
                MessageReaction.message_id == message_id,
                MessageReaction.user_id == user_id
            )
        )
    )
    reaction = result.scalar_one_or_none()
    
    if not reaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No reaction found"
        )
    
    # Get message for notification
    msg_result = await db.execute(select(Message).where(Message.id == message_id))
    message = msg_result.scalar_one_or_none()
    
    await db.delete(reaction)
    await db.commit()
    
    # Get updated reactions summary
    reactions_summary = await _get_reactions_summary(db, message_id)
    
    # Broadcast removal
    if message:
        chat_user_ids = []
        if message.group_id:
            members_result = await db.execute(
                select(GroupMember.user_id).where(GroupMember.group_id == message.group_id)
            )
            chat_user_ids = [m[0] for m in members_result.fetchall()]
        else:
            chat_user_ids = [message.sender_id, message.recipient_id]
        
        ws_payload = {
            "message_id": message_id,
            "user_id": user_id,
            "emoji": None,
            "action": "removed",
            "reactions": [r.model_dump() for r in reactions_summary],
            "group_id": message.group_id,
            "chat_id": message.recipient_id if not message.group_id else None,
        }
        
        ws_message = WSMessage(
            type=WSMessageType.MESSAGE_REACTION,
            payload=ws_payload
        )
        
        for uid in chat_user_ids:
            if uid:
                await ws_manager.send_to_user(uid, ws_message)
    
    return {"action": "removed", "message_id": message_id}


@router.get("/{message_id}/reactions", response_model=ReactionsResponse)
async def get_reactions(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get all reactions for a message with user details."""
    # Verify message exists
    msg_result = await db.execute(select(Message).where(Message.id == message_id))
    message = msg_result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Check access
    has_access = False
    if message.group_id:
        member_result = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == message.group_id,
                    GroupMember.user_id == user_id
                )
            )
        )
        has_access = member_result.scalar_one_or_none() is not None
    else:
        has_access = user_id in [message.sender_id, message.recipient_id]
    
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    reactions_summary = await _get_reactions_summary(db, message_id)
    
    # Get current user's reaction
    user_reaction_result = await db.execute(
        select(MessageReaction.emoji).where(
            and_(
                MessageReaction.message_id == message_id,
                MessageReaction.user_id == user_id
            )
        )
    )
    user_reaction = user_reaction_result.scalar_one_or_none()
    
    return ReactionsResponse(
        message_id=message_id,
        reactions=reactions_summary,
        user_reaction=user_reaction
    )


async def _get_reactions_summary(db: AsyncSession, message_id: str) -> list[ReactionSummary]:
    """Get aggregated reactions for a message."""
    # Get all reactions with user info
    result = await db.execute(
        select(MessageReaction, User.display_name)
        .join(User, MessageReaction.user_id == User.id)
        .where(MessageReaction.message_id == message_id)
        .order_by(MessageReaction.created_at)
    )
    reactions_data = result.fetchall()
    
    # Group by emoji
    emoji_groups: dict[str, list[ReactionUserInfo]] = {}
    for reaction, display_name in reactions_data:
        if reaction.emoji not in emoji_groups:
            emoji_groups[reaction.emoji] = []
        emoji_groups[reaction.emoji].append(
            ReactionUserInfo(user_id=reaction.user_id, display_name=display_name)
        )
    
    # Build summary
    return [
        ReactionSummary(emoji=emoji, count=len(users), users=users)
        for emoji, users in emoji_groups.items()
    ]




# ============== CHANNEL COMMENTS (v3.11.10) ==============

@router.get("/{message_id}/comments")
async def get_comments(
    message_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Get comments (replies) for a specific message.
    Used for channel post comment threads.
    Returns comments ordered chronologically (oldest first).
    """
    # Verify the parent message exists
    parent_result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    parent_msg = parent_result.scalar_one_or_none()
    if not parent_msg:
        raise HTTPException(status_code=404, detail="Message not found")

    # Verify access: user must be a member of the group (or participant in DM)
    if parent_msg.group_id:
        from app.models.group import GroupMember
        member_check = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == parent_msg.group_id,
                    GroupMember.user_id == user_id,
                )
            )
        )
        if not member_check.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Not a member of this group")
    else:
        # DM — user must be sender or recipient
        if user_id not in (parent_msg.sender_id, parent_msg.recipient_id):
            raise HTTPException(status_code=403, detail="Access denied")

    # Fetch comments (replies to this message)
    # КАО#294: `deleted_for_sender` is OVERLOADED — delete_message sets it both for "delete for everyone"
    # (together with deleted_for_recipient) AND for a GROUP sender deleting their OWN message just for
    # themselves. Filtering on it alone therefore hid a comment from EVERY viewer as soon as its author
    # removed it for themselves. Distinguish the cases instead:
    from app.models.message import MessageUserDeletion
    deleted_by_user = select(MessageUserDeletion.message_id).where(
        MessageUserDeletion.user_id == user_id
    ).scalar_subquery()
    result = await db.execute(
        select(Message).where(
            and_(
                Message.reply_to_id == message_id,
                # deleted for everyone → both flags set
                ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),
                # this viewer deleted it for themselves (group, non-sender path)
                ~Message.id.in_(deleted_by_user),
                # this viewer is the author and deleted it for themselves
                ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),
                # this viewer is the DM recipient and deleted it for themselves
                ~and_(Message.recipient_id == user_id, Message.deleted_for_recipient == True),
            )
        )
        .order_by(Message.created_at.asc())
        .limit(limit)
    )
    comments = result.scalars().all()

    # Build response with sender info
    response = []
    for comment in comments:
        sender_result = await db.execute(select(User).where(User.id == comment.sender_id))
        sender = sender_result.scalar_one_or_none()
        response.append({
            "id": comment.id,
            "sender_id": comment.sender_id,
            "sender_name": sender.display_name if sender else "Unknown",
            "sender_username": sender.username if sender else "unknown",
            "encrypted_payload": comment.encrypted_payload,
            "created_at": comment.created_at.isoformat() if comment.created_at else None,
            "reply_to_id": comment.reply_to_id,
        })

    return {"comments": response, "total": len(response)}

# ============== SEARCH ==============

import base64

def decode_message_text(encrypted_payload: str) -> str:
    """Decode base64 message to plaintext for search.
    КАО#163 (SER#15/27): E2EE payloads are JSON envelopes wrapping ciphertext — they are NOT
    searchable plaintext. Skip them so search doesn't false-match on envelope keywords/base64
    or pretend to search ciphertext. (Plaintext search of E2EE must happen client-side.)"""
    try:
        decoded = base64.b64decode(encrypted_payload).decode('utf-8')
        stripped = decoded.lstrip()
        if stripped.startswith('{') and ('"message"' in decoded or '"group"' in decoded or '"v":' in decoded):
            return ""
        return decoded
    except Exception:
        return ""


@router.get("/search")
async def search_messages(
    q: str = Query(..., min_length=1, max_length=100, description="Search query"),
    chat_id: str | None = Query(None, description="Search in specific direct chat"),
    group_id: str | None = Query(None, description="Search in specific group"),
    exact: bool = Query(default=False, description="Exact match (True) or contains (False)"),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Search messages by text content.
    
    - No chat_id/group_id: Global search across all user's chats
    - With chat_id: Search in specific direct chat
    - With group_id: Search in specific group
    - exact=False (default): Search for substring matches
    - exact=True: Search for exact matches only
    
    Returns messages grouped by chat for global search,
    or list of messages for chat-specific search.
    """
    query_lower = q.lower()
    
    def text_matches(text: str) -> bool:
        """Check if text matches the query based on exact flag."""
        text_lower = text.lower()
        if exact:
            return text_lower == query_lower
        else:
            return query_lower in text_lower
    
    if group_id:
        # Search in specific group
        # Verify membership
        member_check = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id
                )
            )
        )
        if not member_check.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="Not a member of this group")

        # КАО#369: КАО#336 added the two deleted_for_* predicates but omitted the MessageUserDeletion
        # subquery — and for a GROUP message that table is the ONLY place a non-sender's "delete for me" is
        # recorded (delete_message routes that case there and never touches the row flags; a group row has
        # recipient_id NULL so deleted_for_recipient is never set either). Search was therefore the one
        # reader that handed a member back a message they had deleted for themselves. Every sibling query
        # (/history pinned filter, get_comments, get_group_messages) already applies all three predicates.
        # Channels post plain base64, so the resurfaced text is directly readable.
        from app.models.message import MessageUserDeletion
        _deleted_by_viewer = select(MessageUserDeletion.message_id).where(
            MessageUserDeletion.user_id == user_id
        ).scalar_subquery()

        # Get all group messages
        result = await db.execute(
            select(Message).where(
                Message.group_id == group_id,
                # КАО#336: search bypassed every deletion rule, so a message deleted for everyone was
                # still findable (with its payload) through the search endpoint.
                ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),
                ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),
                ~Message.id.in_(_deleted_by_viewer),  # КАО#369
            )
            .order_by(Message.created_at.desc())
            .limit(500)  # Limit for performance
        )
        all_messages = result.scalars().all()
        
        # Filter by decoded text
        matching = []
        for msg in all_messages:
            text = decode_message_text(msg.encrypted_payload)
            if text_matches(text):
                matching.append(msg)
                if len(matching) >= limit:
                    break
        
        # Build response
        response = []
        for msg in matching:
            sender_result = await db.execute(select(User).where(User.id == msg.sender_id))
            sender = sender_result.scalar_one_or_none()
            response.append({
                "id": msg.id,
                "group_id": msg.group_id,
                "sender_id": msg.sender_id,
                "sender_name": sender.display_name if sender else "Unknown",
                "encrypted_payload": msg.encrypted_payload,
                "created_at": msg.created_at.isoformat() if msg.created_at else None,
            })
        
        return {"messages": response, "total": len(response)}
    
    elif chat_id:
        # Search in specific direct chat
        result = await db.execute(
            select(Message).where(
                and_(
                    or_(
                        and_(Message.sender_id == user_id, Message.recipient_id == chat_id),
                        and_(Message.sender_id == chat_id, Message.recipient_id == user_id),
                    ),
                    or_(
                        and_(Message.sender_id == user_id, Message.deleted_for_sender == False),
                        and_(Message.recipient_id == user_id, Message.deleted_for_recipient == False),
                    )
                )
            ).order_by(Message.created_at.desc()).limit(500)
        )
        all_messages = result.scalars().all()
        
        # Filter by decoded text
        matching = []
        for msg in all_messages:
            text = decode_message_text(msg.encrypted_payload)
            if text_matches(text):
                matching.append(msg)
                if len(matching) >= limit:
                    break
        
        response = []
        for msg in matching:
            response.append({
                "id": msg.id,
                "chat_id": chat_id,
                "sender_id": msg.sender_id,
                "encrypted_payload": msg.encrypted_payload,
                "created_at": msg.created_at.isoformat() if msg.created_at else None,
            })
        
        return {"messages": response, "total": len(response)}
    
    else:
        # Global search across all chats
        # Get direct messages
        direct_result = await db.execute(
            select(Message).where(
                and_(
                    or_(Message.sender_id == user_id, Message.recipient_id == user_id),
                    Message.group_id.is_(None),
                    or_(
                        and_(Message.sender_id == user_id, Message.deleted_for_sender == False),
                        and_(Message.recipient_id == user_id, Message.deleted_for_recipient == False),
                    )
                )
            ).order_by(Message.created_at.desc()).limit(1000)
        )
        direct_messages = direct_result.scalars().all()
        
        # Get group messages
        user_groups_result = await db.execute(
            select(GroupMember.group_id).where(GroupMember.user_id == user_id)
        )
        user_group_ids = [g[0] for g in user_groups_result.fetchall()]
        
        group_messages = []
        if user_group_ids:
            # КАО#369: same omission as the group-scoped branch above.
            from app.models.message import MessageUserDeletion
            _deleted_by_viewer_global = select(MessageUserDeletion.message_id).where(
                MessageUserDeletion.user_id == user_id
            ).scalar_subquery()
            group_result = await db.execute(
                select(Message).where(
                    Message.group_id.in_(user_group_ids),
                    # КАО#336: same deletion rules for the global (all-groups) search.
                    ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),
                    ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),
                    ~Message.id.in_(_deleted_by_viewer_global),  # КАО#369
                )
                .order_by(Message.created_at.desc()).limit(1000)
            )
            group_messages = group_result.scalars().all()
        
        # Group results by chat
        chats_with_matches = {}
        
        # Process direct messages
        for msg in direct_messages:
            text = decode_message_text(msg.encrypted_payload)
            if not text_matches(text):
                continue
                
            other_user_id = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
            if other_user_id not in chats_with_matches:
                other_user_result = await db.execute(select(User).where(User.id == other_user_id))
                other_user = other_user_result.scalar_one_or_none()
                chats_with_matches[other_user_id] = {
                    "chat_id": other_user_id,
                    "type": "direct",
                    "name": other_user.display_name if other_user else "Unknown",
                    "match_count": 0,
                    "last_match": None,
                    "last_match_preview": text[:100],
                }
            chats_with_matches[other_user_id]["match_count"] += 1
            if not chats_with_matches[other_user_id]["last_match"] or msg.created_at > chats_with_matches[other_user_id]["last_match"]:
                chats_with_matches[other_user_id]["last_match"] = msg.created_at
                chats_with_matches[other_user_id]["last_match_preview"] = text[:100]
        
        # Process group messages
        for msg in group_messages:
            text = decode_message_text(msg.encrypted_payload)
            if not text_matches(text):
                continue
                
            group_key = f"group_{msg.group_id}"
            if group_key not in chats_with_matches:
                group_result = await db.execute(select(Group).where(Group.id == msg.group_id))
                group = group_result.scalar_one_or_none()
                chats_with_matches[group_key] = {
                    "chat_id": msg.group_id,
                    "type": "group",
                    "name": group.name if group else "Unknown Group",
                    "match_count": 0,
                    "last_match": None,
                    "last_match_preview": text[:100],
                }
            chats_with_matches[group_key]["match_count"] += 1
            if not chats_with_matches[group_key]["last_match"] or msg.created_at > chats_with_matches[group_key]["last_match"]:
                chats_with_matches[group_key]["last_match"] = msg.created_at
                chats_with_matches[group_key]["last_match_preview"] = text[:100]
        
        # Convert to list and sort
        results = list(chats_with_matches.values())
        results.sort(key=lambda x: x["last_match"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        
        for r in results:
            if r["last_match"]:
                r["last_match"] = r["last_match"].isoformat()
        
        return {"chats": results[:limit], "total": len(results)}


# ==================== BATCH OPERATIONS ====================

from pydantic import BaseModel
from typing import List

class BatchDeleteRequest(BaseModel):
    message_ids: List[str]
    for_everyone: bool = False


@router.post("/batch/delete", status_code=status.HTTP_200_OK)
async def batch_delete_messages(
    request: BatchDeleteRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Delete multiple messages at once.
    
    - for_everyone=False: Delete only for current user
    - for_everyone=True: Delete for all participants (only works for own messages)
    
    Returns list of successfully deleted message IDs and any errors.
    """
    deleted = []
    errors = []
    
    for message_id in request.message_ids:
        try:
            result = await db.execute(
                select(Message).where(Message.id == message_id)
            )
            message = result.scalar_one_or_none()
            
            if not message:
                errors.append({"message_id": message_id, "error": "Not found"})
                continue
            
            # Check if user is participant
            is_participant = False
            is_sender = message.sender_id == user_id
            
            if message.group_id:
                member_result = await db.execute(
                    select(GroupMember).where(
                        and_(GroupMember.group_id == message.group_id, GroupMember.user_id == user_id)
                    )
                )
                is_participant = member_result.scalar_one_or_none() is not None
            else:
                is_participant = (message.sender_id == user_id or message.recipient_id == user_id)
            
            if not is_participant:
                errors.append({"message_id": message_id, "error": "Not authorized"})
                continue
            
            if request.for_everyone:
                # Only sender can delete for everyone
                if not is_sender:
                    errors.append({"message_id": message_id, "error": "Only sender can delete for everyone"})
                    continue
                
                message.deleted_for_sender = True
                message.deleted_for_recipient = True

                # КАО#368: same as delete_message — free the pin slot a retracted message would otherwise
                # occupy invisibly forever.
                await db.execute(delete(PinnedMessage).where(PinnedMessage.message_id == message_id))
                message.is_pinned = False

                # Notify via WebSocket
                delete_msg = WSMessage(
                    type=WSMessageType.MESSAGE_DELETED,
                    payload={
                        "message_id": message_id,
                        "deleted_by": user_id,
                        "for_everyone": True,
                    }
                )
                
                if message.group_id:
                    members_result = await db.execute(
                        select(GroupMember.user_id).where(GroupMember.group_id == message.group_id)
                    )
                    for m in members_result.fetchall():
                        await ws_manager.send_to_user(m[0], delete_msg)
                else:
                    if message.recipient_id:
                        await ws_manager.send_to_user(message.recipient_id, delete_msg)
                    await ws_manager.send_to_user(user_id, delete_msg)
            else:
                # Delete only for current user
                if message.group_id:
                    if is_sender:
                        message.deleted_for_sender = True
                    else:
                        from app.models.message import MessageUserDeletion
                        # КАО#249 (#16): idempotent — a duplicate (message_id,user_id) would raise
                        # IntegrityError on the UniqueConstraint and abort the WHOLE batch commit.
                        dup = await db.execute(
                            select(MessageUserDeletion).where(
                                and_(MessageUserDeletion.message_id == message_id,
                                     MessageUserDeletion.user_id == user_id)
                            )
                        )
                        if dup.scalar_one_or_none() is None:
                            db.add(MessageUserDeletion(message_id=message_id, user_id=user_id))
                else:
                    if is_sender:
                        message.deleted_for_sender = True
                    else:
                        message.deleted_for_recipient = True
                
                # Notify current user's other devices
                await ws_manager.send_to_user(
                    user_id,
                    WSMessage(
                        type=WSMessageType.MESSAGE_DELETED,
                        payload={
                            "message_id": message_id,
                            "deleted_by": user_id,
                            "for_everyone": False,
                        }
                    )
                )
            
            deleted.append(message_id)
            
        except Exception as e:
            errors.append({"message_id": message_id, "error": str(e)})
    
    await db.commit()
    
    return {
        "deleted": deleted,
        "deleted_count": len(deleted),
        "errors": errors,
        "error_count": len(errors)
    }
