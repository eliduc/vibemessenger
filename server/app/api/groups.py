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
Group chat API endpoints.
"""
import os
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, delete
from sqlalchemy.exc import IntegrityError  # КАО#250 (#15): graceful concurrent membership inserts

from app.database import get_db
from app.models.group import (
    Group, GroupMember, GroupRole, GroupInvite,
    GroupCreate, GroupUpdate, GroupResponse, GroupListItem,
    GroupMemberInfo, AddMembersRequest, RemoveMemberRequest,
    GroupInviteResponse, InviteAction,
    # New for v3.9.0
    InviteLinkResponse, GroupPublicInfo, ChangeRoleRequest, GroupSettingsUpdate,
    can_manage_role, ROLE_HIERARCHY,
)
from app.models.message import Message, MessageResponse, WSMessage, WSMessageType, MessageReaction, MessageUserDeletion
from app.models.user import User, PushSubscription
from app.api.auth import get_current_user_id
from app.services.websocket_manager import ws_manager
from app.services.push_service import push_service

GROUP_AVATAR_DIR = "/app/data/group_avatars"
os.makedirs(GROUP_AVATAR_DIR, exist_ok=True)

# Regex pattern for valid group avatar filenames: UUID_hex.extension
GROUP_AVATAR_FILENAME_PATTERN = re.compile(
    r'^[a-f0-9\-]{36}_[a-f0-9]{8}\.(jpg|jpeg|png|gif|webp)$',
    re.IGNORECASE
)

# Allowed image types for avatars
ALLOWED_AVATAR_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
ALLOWED_AVATAR_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}


def validate_group_avatar_filename(filename: str, base_dir: str) -> str:
    """
    Validate group avatar filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to validate
        base_dir: The base directory for avatars
        
    Returns:
        Safe absolute filepath
        
    Raises:
        HTTPException: If filename is invalid or attempts path traversal
    """
    # Check for path traversal attempts
    if not filename or '..' in filename or '/' in filename or '\\' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Extract only the basename (extra safety)
    safe_filename = os.path.basename(filename)
    
    # Validate filename format
    if not GROUP_AVATAR_FILENAME_PATTERN.match(safe_filename):
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    # Build and resolve the path
    base_path = Path(base_dir).resolve()
    file_path = (base_path / safe_filename).resolve()
    
    # Ensure the resolved path is within base directory
    try:
        file_path.relative_to(base_path)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    return str(file_path)

router = APIRouter(prefix="/groups", tags=["Groups"])


async def get_user_info(db: AsyncSession, user_id: str) -> dict:
    """Get user info by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user:
        return {"username": user.username, "display_name": user.display_name or user.username, "avatar_url": user.avatar_url}
    return {"username": "Unknown", "display_name": "Unknown", "avatar_url": None}


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    group_data: GroupCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Create a new group chat and send invites to members."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Creating group '{group_data.name}' by user {user_id}")
    
    # Create group
    group = Group(
        name=group_data.name,
        description=group_data.description,
        created_by=user_id,
        is_channel=group_data.is_channel,  # v3.11.10: Channel support
    )
    db.add(group)
    await db.flush()
    logger.info(f"Group created with id {group.id}")
    
    # Add creator as owner
    owner_member = GroupMember(
        group_id=group.id,
        user_id=user_id,
        role="owner",
    )
    db.add(owner_member)
    
    # Get creator info
    members_info = []
    creator_info = await get_user_info(db, user_id)
    members_info.append(GroupMemberInfo(
        user_id=user_id,
        username=creator_info["username"],
        display_name=creator_info["display_name"],
        role="owner",
        joined_at=owner_member.joined_at or datetime.now(timezone.utc),
    ))
    
    # Collect invites to send after commit
    invites_to_notify = []
    
    # Send invites to members (don't add them directly)
    # v3.11.10: Channels start with owner only, no initial members
    for member_id in ([] if group_data.is_channel else group_data.member_ids):
        if member_id == user_id:
            continue
            
        # Verify user exists
        result = await db.execute(select(User).where(User.id == member_id))
        if not result.scalar_one_or_none():
            continue
        
        # Create invite with explicit ID
        from uuid import uuid4
        invite_id = str(uuid4())
        
        invite = GroupInvite(
            id=invite_id,
            group_id=group.id,
            inviter_id=user_id,
            invitee_id=member_id,
            status="pending",
        )
        db.add(invite)
        
        # Get push subscriptions for this user (include ID for cleanup)
        push_result = await db.execute(
            select(PushSubscription).where(PushSubscription.user_id == member_id)
        )
        push_subs = push_result.scalars().all()
        push_subscriptions = [
            {
                "id": sub.id,
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth}
            }
            for sub in push_subs
        ]
        
        # Save for notification after commit
        invites_to_notify.append({
            "member_id": member_id,
            "invite_id": invite_id,
            "group_id": group.id,
            "group_name": group.name,
            "inviter_name": creator_info["display_name"],
            "push_subscriptions": push_subscriptions,
        })
    
    # Commit all DB changes first
    await db.commit()
    logger.info(f"Group committed, sending {len(invites_to_notify)} invites")
    
    # Send WebSocket and Push notifications in background (don't wait)
    async def send_invites():
        from app.database import async_session_maker
        
        logger.info(f"Starting to send {len(invites_to_notify)} invite notifications")
        subscriptions_to_remove = []
        
        for invite_data in invites_to_notify:
            try:
                logger.info(f"Sending invite to {invite_data['member_id']}, push subs: {len(invite_data['push_subscriptions'])}")
                # WebSocket notification
                ws_result = await ws_manager.send_to_user(
                    invite_data["member_id"],
                    WSMessage(
                        type=WSMessageType.NEW_MESSAGE,
                        payload={
                            "type": "group_invite",
                            "invite_id": invite_data["invite_id"],
                            "group_id": invite_data["group_id"],
                            "group_name": invite_data["group_name"],
                            "inviter_id": user_id,
                            "inviter_name": invite_data["inviter_name"],
                        }
                    )
                )
                logger.info(f"WS invite sent to {invite_data['member_id']}: {ws_result}")
                
                # Push notification (always send - SW will handle focus check)
                for sub in invite_data["push_subscriptions"]:
                    try:
                        sub_info = {"endpoint": sub["endpoint"], "keys": sub["keys"]}
                        push_result = push_service.send_group_invite_notification(
                            sub_info,
                            invite_data["inviter_name"],
                            invite_data["group_name"],
                            invite_data["group_id"]
                        )
                        if push_result.should_remove:
                            subscriptions_to_remove.append(sub["id"])
                            logger.info(f"Marking subscription {sub['id']} for removal (invalid)")
                        elif push_result.success:
                            logger.info(f"Push invite sent to {invite_data['member_id']}")
                    except Exception as e:
                        logger.error(f"Push invite failed for {invite_data['member_id']}: {e}")
                        
            except Exception as e:
                logger.error(f"Failed to send invite notification to {invite_data['member_id']}: {e}")
        
        # Remove invalid subscriptions from DB
        if subscriptions_to_remove:
            try:
                async with async_session_maker() as cleanup_db:
                    await cleanup_db.execute(
                        delete(PushSubscription).where(PushSubscription.id.in_(subscriptions_to_remove))
                    )
                    await cleanup_db.commit()
                    logger.info(f"Removed {len(subscriptions_to_remove)} invalid push subscriptions")
            except Exception as e:
                logger.error(f"Failed to cleanup invalid subscriptions: {e}")
        
        logger.info("All invite notifications processed")
    
    # Fire and forget - don't block the response
    import asyncio
    asyncio.create_task(send_invites())
    
    logger.info(f"Group creation complete")
    
    return GroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.created_by,
        created_at=group.created_at,
        member_count=len(members_info),
        members=members_info,
        is_channel=group.is_channel,  # v3.11.10
    )


@router.get("", response_model=list[GroupListItem])
async def get_my_groups(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get all groups the user is a member of."""
    # Get groups where user is a member
    result = await db.execute(
        select(Group, func.count(GroupMember.id).label("member_count"))
        .join(GroupMember, Group.id == GroupMember.group_id)
        .where(
            and_(
                GroupMember.user_id == user_id,
                Group.is_deleted == False,
            )
        )
        .group_by(Group.id)
    )
    
    groups = []
    for row in result.all():
        group = row[0]
        member_count = row[1]
        
        # Get last message
        msg_result = await db.execute(
            select(Message)
            .where(Message.group_id == group.id)
            .order_by(Message.created_at.desc())
            .limit(1)
        )
        last_msg = msg_result.scalar_one_or_none()
        
        # Get unread count
        member_result = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group.id,
                    GroupMember.user_id == user_id,
                )
            )
        )
        membership = member_result.scalar_one_or_none()
        
        unread_count = 0
        if membership and membership.last_read_at:
            unread_result = await db.execute(
                select(func.count(Message.id)).where(
                    and_(
                        Message.group_id == group.id,
                        Message.created_at > membership.last_read_at,
                        Message.sender_id != user_id,
                    )
                )
            )
            unread_count = unread_result.scalar() or 0
        
        groups.append(GroupListItem(
            id=group.id,
            name=group.name,
            description=group.description,
            member_count=member_count,
                is_channel=group.is_channel,
            last_message=None,  # КАО#061: was last_msg.encrypted_payload[:50] — leaked E2E ciphertext prefix as preview; client derives preview from decrypted messages
            last_message_at=last_msg.created_at if last_msg else None,
            unread_count=unread_count,
        ))
    
    # Sort by last message time
    groups.sort(key=lambda g: g.last_message_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    
    return groups


# ============== INVITE ENDPOINTS ==============
# These must be defined BEFORE /{group_id} routes to avoid path conflicts

@router.get("/invites/pending", response_model=list[GroupInviteResponse])
async def get_pending_invites(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get all pending group invites for the current user."""
    try:
        result = await db.execute(
            select(GroupInvite).where(
                and_(
                    GroupInvite.invitee_id == user_id,
                    func.lower(GroupInvite.status) == "pending",
                )
            ).order_by(GroupInvite.created_at.desc())
        )
        invites = result.scalars().all()
    except Exception as e:
        # Table might not exist yet
        import logging
        logging.error(f"Error getting invites: {e}")
        return []
    
    response = []
    for invite in invites:
        # Get group info
        group_result = await db.execute(select(Group).where(Group.id == invite.group_id))
        group = group_result.scalar_one_or_none()
        if not group or group.is_deleted:
            continue
        
        # Get inviter info
        inviter_info = await get_user_info(db, invite.inviter_id)
        
        response.append(GroupInviteResponse(
            id=invite.id,
            group_id=invite.group_id,
            group_name=group.name,
            inviter_id=invite.inviter_id,
            inviter_name=inviter_info["display_name"],
            status=invite.status,  # Already a string in DB
            created_at=invite.created_at,
        ))
    
    return response


@router.post("/invites/{invite_id}/respond", status_code=status.HTTP_200_OK)
async def respond_to_invite(
    invite_id: str,
    action: InviteAction,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Accept or decline a group invite."""
    # Get invite
    result = await db.execute(
        select(GroupInvite).where(
            and_(
                GroupInvite.id == invite_id,
                GroupInvite.invitee_id == user_id,
            )
        )
    )
    invite = result.scalar_one_or_none()
    
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
    
    if invite.status != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invite already responded")
    
    # Get group
    group_result = await db.execute(select(Group).where(Group.id == invite.group_id))
    group = group_result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    # КАО#254 Round-2: snapshot group fields — the IntegrityError rollback below EXPIRES the `group`
    # ORM instance, so any later group.* read (notify/return) would raise MissingGreenlet.
    g_id = group.id
    g_name = group.name
    g_created_by = group.created_by
    g_is_channel = group.is_channel

    invite.responded_at = datetime.now(timezone.utc)

    if action.action == "accept":
        invite.status = "accepted"

        # Add user as member only if not already one (КАО#254 #37: idempotent vs the unique constraint)
        already = await db.execute(
            select(GroupMember).where(
                and_(GroupMember.group_id == invite.group_id, GroupMember.user_id == user_id)
            )
        )
        if not already.scalar_one_or_none():
            db.add(GroupMember(
                group_id=invite.group_id,
                user_id=user_id,
                role="subscriber" if g_is_channel else "member",
            ))

        try:
            await db.commit()
        except IntegrityError:
            # КАО#254 (#37): concurrent accept already created the membership — mark the invite
            # accepted idempotently in a fresh transaction.
            await db.rollback()
            inv2 = (await db.execute(
                select(GroupInvite).where(GroupInvite.id == invite_id)
            )).scalar_one_or_none()
            if inv2 and inv2.status == "pending":  # КАО#254 R3: don't flip a concurrently-declined invite
                inv2.status = "accepted"
                inv2.responded_at = datetime.now(timezone.utc)
                await db.commit()

        # КАО#253 (#38): notify owner only after the membership is committed (group.* snapshotted above)
        await ws_manager.send_to_user(
            g_created_by,
            WSMessage(
                type=WSMessageType.NEW_MESSAGE,
                payload={
                    "type": "invite_accepted",
                    "group_id": g_id,
                    "group_name": g_name,
                    "user_id": user_id,
                }
            )
        )

        return {"status": "accepted", "group_id": g_id, "group_name": g_name}
    else:
        invite.status = "declined"
        await db.commit()
        
        return {"status": "declined"}


# ============== GROUP DETAIL ENDPOINTS ==============

@router.get("/{group_id}", response_model=GroupResponse)
async def get_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get group details."""
    # Check if user is a member
    member_check = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    if not member_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Get members
    members_result = await db.execute(
        select(GroupMember).where(GroupMember.group_id == group_id)
    )
    members = members_result.scalars().all()
    
    members_info = []
    for member in members:
        info = await get_user_info(db, member.user_id)
        members_info.append(GroupMemberInfo(
            user_id=member.user_id,
            username=info["username"],
            display_name=info["display_name"],
            role=member.role,
            joined_at=member.joined_at,
        ))
    
    return GroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        avatar_url=group.avatar_url,
        created_by=group.created_by,
        created_at=group.created_at,
        member_count=len(members_info),
        members=members_info,
        # v3.9.0 fields
        is_public=group.is_public or False,
        invite_link_enabled=group.invite_link_enabled or False,
        invite_code=group.invite_code,
        is_channel=group.is_channel,  # v3.11.10
    )


@router.get("/{group_id}/members", response_model=list[GroupMemberInfo])
async def get_group_members(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get all members of a group. Any group member can view the member list."""
    # Check if user is a member
    member_check = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    if not member_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")
    
    # Get group to verify it exists and is not deleted
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Get all members
    members_result = await db.execute(
        select(GroupMember).where(GroupMember.group_id == group_id).order_by(GroupMember.joined_at)
    )
    members = members_result.scalars().all()
    
    members_info = []
    for member in members:
        info = await get_user_info(db, member.user_id)
        members_info.append(GroupMemberInfo(
            user_id=member.user_id,
            username=info["username"],
            display_name=info["display_name"],
            role=member.role,
            joined_at=member.joined_at,
        ))
    
    return members_info


@router.put("/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: str,
    update_data: GroupUpdate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Update group info (admin/owner only)."""
    # Check if user is admin or owner
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Update
    if update_data.name:
        group.name = update_data.name
    if update_data.description is not None:
        group.description = update_data.description
    
    await db.commit()
    
    return await get_group(group_id, db, user_id)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Delete a group (owner only)."""
    import asyncio
    import logging
    logger = logging.getLogger(__name__)
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Only owner can delete
    if group.created_by != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group owner can delete the group")
    
    # Get owner info for notification
    owner_info = await get_user_info(db, user_id)
    owner_name = owner_info["display_name"]
    group_name = group.name
    
    # Get all members to notify them
    members_result = await db.execute(
        select(GroupMember).where(GroupMember.group_id == group_id)
    )
    members = members_result.scalars().all()
    
    # Get push subscriptions for all members (except owner) - include ID for cleanup
    members_to_notify = []
    for member in members:
        if member.user_id != user_id:
            push_result = await db.execute(
                select(PushSubscription).where(PushSubscription.user_id == member.user_id)
            )
            push_subs = push_result.scalars().all()
            members_to_notify.append({
                "user_id": member.user_id,
                "push_subscriptions": [
                    {"id": sub.id, "endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}}
                    for sub in push_subs
                ]
            })
    
    # Soft delete first
    group.is_deleted = True
    await db.commit()
    
    # Send notifications in background
    async def notify_members():
        from app.database import async_session_maker
        
        subscriptions_to_remove = []
        
        for member_data in members_to_notify:
            try:
                # WebSocket notification
                await ws_manager.send_to_user(
                    member_data["user_id"],
                    WSMessage(
                        type=WSMessageType.NEW_MESSAGE,
                        payload={
                            "type": "group_deleted",
                            "group_id": group_id,
                            "group_name": group_name,
                            "owner_name": owner_name,
                        }
                    )
                )
                logger.info(f"WS group_deleted sent to {member_data['user_id']}")
                
                # Push notification (always send - SW will handle focus check)
                for sub in member_data["push_subscriptions"]:
                    try:
                        sub_info = {"endpoint": sub["endpoint"], "keys": sub["keys"]}
                        push_result = push_service.send_group_deleted_notification(
                            sub_info, owner_name, group_name, group_id
                        )
                        if push_result.should_remove:
                            subscriptions_to_remove.append(sub["id"])
                            logger.info(f"Marking subscription {sub['id']} for removal (invalid)")
                        elif push_result.success:
                            logger.info(f"Push group_deleted sent to {member_data['user_id']}")
                    except Exception as e:
                        logger.error(f"Push failed for {member_data['user_id']}: {e}")
                        
            except Exception as e:
                logger.error(f"Failed to notify {member_data['user_id']}: {e}")
        
        # Remove invalid subscriptions from DB
        if subscriptions_to_remove:
            try:
                async with async_session_maker() as cleanup_db:
                    await cleanup_db.execute(
                        delete(PushSubscription).where(PushSubscription.id.in_(subscriptions_to_remove))
                    )
                    await cleanup_db.commit()
                    logger.info(f"Removed {len(subscriptions_to_remove)} invalid push subscriptions")
            except Exception as e:
                logger.error(f"Failed to cleanup invalid subscriptions: {e}")
    
    asyncio.create_task(notify_members())


@router.post("/{group_id}/members", response_model=GroupResponse)
async def add_members(
    group_id: str,
    request: AddMembersRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Add members to a group (admin/owner only)."""
    # Check if user is admin or owner
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    # КАО#250 Round-2: snapshot group fields into locals — a per-member rollback (below) EXPIRES the
    # `group` ORM instance, so any later group.* access would raise MissingGreenlet (async lazy reload).
    group_name = group.name
    group_is_channel = group.is_channel

    # Add members
    newly_added = []  # КАО#253 (#38): notify only AFTER the membership commits
    for new_user_id in request.user_ids:
        # Check if already a member
        existing = await db.execute(
            select(GroupMember).where(
                and_(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == new_user_id,
                )
            )
        )
        if existing.scalar_one_or_none():
            continue

        # Verify user exists and is not a deleted/deactivated account
        # KAO#358: without the is_active filter a DELETED account could be added back into a group,
        # reappearing in the member list as "Deleted account ..." and receiving future invites.
        user_result = await db.execute(
            select(User).where(and_(User.id == new_user_id, User.is_active == True))
        )
        if not user_result.scalar_one_or_none():
            continue

        member = GroupMember(
            group_id=group_id,
            user_id=new_user_id,
            role="subscriber" if group_is_channel else "member",  # КАО#060: subscriber role in channels
        )
        db.add(member)
        # КАО#250 (#15): commit per member so a concurrent add (unique constraint) can't abort the
        # whole batch; on conflict the user is already a member — skip without notifying.
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            continue
        newly_added.append(new_user_id)

    # КАО#253 (#38): WS notifications fire only after the membership rows are durably committed.
    for new_user_id in newly_added:
        await ws_manager.send_to_user(
            new_user_id,
            WSMessage(
                type=WSMessageType.NEW_MESSAGE,
                payload={
                    "type": "group_joined",
                    "group_id": group_id,
                    "group_name": group_name,
                    "added_by": user_id,
                }
            )
        )

    return await get_group(group_id, db, user_id)


@router.delete("/{group_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    group_id: str,
    member_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Remove a member from group (admin/owner or self)."""
    # Check if user is admin/owner or removing themselves
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    current_member = member_result.scalar_one_or_none()
    
    if not current_member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")
    
    # Can remove self, or admin/owner can remove others
    if member_id != user_id and current_member.role not in ['owner', 'admin']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get target member
    target_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == member_id,
            )
        )
    )
    target_member = target_result.scalar_one_or_none()
    
    if not target_member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    
    # Can't remove owner unless they remove themselves
    if target_member.role == 'owner' and member_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot remove group owner")
    
    await db.delete(target_member)
    await db.commit()

    # КАО#253 (#38): notify only after the removal is committed
    await ws_manager.send_to_user(
        member_id,
        WSMessage(
            type=WSMessageType.NEW_MESSAGE,
            payload={
                "type": "group_left",
                "group_id": group_id,
            }
        )
    )


@router.get("/{group_id}/messages")
async def get_group_messages(
    group_id: str,
    before_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get messages from a group chat with reactions."""
    # Check if user is a member
    member_check = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    membership = member_check.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")

    # КАО#001: fetch group (was referenced undefined below for channel comment counts -> NameError 500)
    group_result = await db.execute(select(Group).where(Group.id == group_id))
    group = group_result.scalar_one_or_none()

    # Build query - exclude messages deleted by sender or deleted by current user
    # Subquery to get message IDs deleted by this user
    deleted_by_user = select(MessageUserDeletion.message_id).where(
        MessageUserDeletion.user_id == user_id
    ).scalar_subquery()
    
    query = select(Message).where(
        and_(
            Message.group_id == group_id,
            # КАО#321 (same overloaded flag as КАО#294): `deleted_for_sender` means TWO different things —
            # delete-for-everyone sets it together with deleted_for_recipient (messages.py:795-796), while a
            # group AUTHOR deleting their own message just for themselves sets only this one
            # (messages.py:826-827). Testing it alone therefore hid an author's for-me delete from EVERY
            # member — and inconsistently so, since the comment panel (get_comments) now shows it.
            ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),  # deleted for everyone
            ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),           # author's own for-me delete
            ~Message.id.in_(deleted_by_user)  # Not deleted by current user
        )
    )
    
    if before_id:
        result = await db.execute(select(Message).where(Message.id == before_id))
        cursor_msg = result.scalar_one_or_none()
        if cursor_msg:
            query = query.where(Message.created_at < cursor_msg.created_at)
    
    query = query.order_by(Message.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    messages = list(reversed(result.scalars().all()))
    
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
    
    # Add sender names and reactions
    # v3.11.10: Get comment counts for channel posts
    comment_counts = {}
    if group and group.is_channel:  # КАО#001: group is now defined above
        from sqlalchemy import func as sqlfunc
        cc_result = await db.execute(
            select(Message.reply_to_id, sqlfunc.count(Message.id))
            .where(
                and_(
                    Message.group_id == group_id,
                    Message.reply_to_id.isnot(None),
                    # КАО#339: use the same three predicates as the message list (КАО#321) and
                    # get_comments (КАО#294) — the single-flag test made the badge disagree with the
                    # panel, undercounting whenever an author had deleted their own comment for themselves.
                    ~and_(Message.deleted_for_sender == True, Message.deleted_for_recipient == True),
                    ~and_(Message.sender_id == user_id, Message.deleted_for_sender == True),
                    ~Message.id.in_(deleted_by_user),
                )
            )
            .group_by(Message.reply_to_id)
        )
        comment_counts = dict(cc_result.fetchall())

    response_messages = []
    for msg in messages:
        sender_info = await get_user_info(db, msg.sender_id)
        
        # Build reactions list
        msg_reactions = []
        if msg.id in reactions_map:
            for emoji, users in reactions_map[msg.id].items():
                msg_reactions.append({
                    "emoji": emoji,
                    "count": len(users),
                    "users": users
                })
        
        # Parse mentions from JSON
        import json
        mentions_list = None
        if msg.mentions:
            try:
                mentions_list = json.loads(msg.mentions)
            except:
                pass
        
        response = {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "recipient_id": msg.recipient_id,
            "group_id": msg.group_id,
            "message_type": msg.message_type,
            "encrypted_payload": msg.encrypted_payload,
            "file_id": msg.file_id,
            "status": msg.status,
            "client_message_id": msg.client_message_id,
            "created_at": msg.created_at,
            "delivered_at": msg.delivered_at,
            "expires_at": msg.expires_at,
            "edited_at": msg.edited_at,
            # КАО#375: the sender's own self-copy. Without it the client's own-message recovery branch was
            # DEAD CODE for groups (it is guarded on this very field), and a member never holds their OWN
            # sender key — memberKeys is only ever filled from OTHER members' distributions — so
            # decryptGroupMessage(groupId, ownUserId) always throws. The only other copy of the plaintext is
            # the local IndexedDB cache, which is purged after 30 days, wiped by an E2EE reset and absent on
            # a second device: at that point the user's OWN group messages become permanently unreadable to
            # them while every other member still reads them. The 1:1 history path returns this field for
            # free via MessageResponse; this endpoint builds its dict by hand and simply omitted it.
            # Scoped to the sender: the blob is sealed with a per-user self key and is useless to anyone
            # else, so there is no reason to ship it to every member.
            "encrypted_for_self": msg.encrypted_for_self if msg.sender_id == user_id else None,
            "is_pinned": msg.is_pinned,  # КАО#340: never returned, so КАО#312's client-side carry was a no-op and group pin badges vanished on reopen
            "forwarded_from_id": msg.forwarded_from_id,
            "forwarded_from_name": msg.forwarded_from_name,
            "reply_to_id": msg.reply_to_id,
            "sender_name": sender_info["display_name"],
            "reactions": msg_reactions,
            "mentions": mentions_list,
            "comment_count": comment_counts.get(msg.id, 0),
        }
        response_messages.append(response)
    
    # Update last read
    membership.last_read_at = datetime.now(timezone.utc)
    await db.commit()
    
    return response_messages


@router.post("/{group_id}/avatar")
async def upload_group_avatar(
    group_id: str,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Upload group avatar. Only owner can upload."""
    import aiofiles
    
    # Check group exists
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check user is owner
    if group.created_by != user_id:
        raise HTTPException(status_code=403, detail="Only group owner can change avatar")
    
    # Validate file type - strict whitelist
    if not file.content_type or file.content_type not in ALLOWED_AVATAR_TYPES:
        raise HTTPException(status_code=400, detail="File must be an image (JPEG, PNG, GIF, or WebP)")
    
    # Validate and sanitize extension
    ext = 'jpg'  # default
    if file.filename and "." in file.filename:
        ext = file.filename.rsplit(".", 1)[-1].lower()
        if ext not in ALLOWED_AVATAR_EXTENSIONS:
            ext = 'jpg'
    
    # Generate safe unique filename
    filename = f"{group_id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(GROUP_AVATAR_DIR, filename)
    
    # Max avatar size: 5MB
    max_size = 5 * 1024 * 1024
    total_size = 0
    chunk_size = 256 * 1024  # 256KB chunks
    
    # Read and write in chunks with size check
    try:
        async with aiofiles.open(filepath, 'wb') as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                
                total_size += len(chunk)
                if total_size > max_size:
                    await f.close()
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    raise HTTPException(status_code=400, detail="File too large (max 5MB)")
                
                await f.write(chunk)
    except HTTPException:
        raise
    except Exception:
        if os.path.exists(filepath):
            os.remove(filepath)
        raise HTTPException(status_code=500, detail="Failed to save avatar")
    
    # Delete old avatar if exists (with path traversal protection)
    if group.avatar_url:
        old_filename = group.avatar_url.split("/")[-1]
        try:
            old_filepath = validate_group_avatar_filename(old_filename, GROUP_AVATAR_DIR)
            if os.path.exists(old_filepath):
                os.remove(old_filepath)
        except HTTPException:
            pass  # Ignore invalid filename errors during delete
    
    # Update group
    avatar_url = f"/api/v1/groups/avatar/{filename}"
    group.avatar_url = avatar_url
    await db.commit()
    
    return {"avatar_url": avatar_url}


@router.get("/avatar/{filename}")
async def get_group_avatar(filename: str):
    """Get group avatar image with path traversal protection."""
    from fastapi.responses import FileResponse
    
    # Validate filename and get safe filepath
    filepath = validate_group_avatar_filename(filename, GROUP_AVATAR_DIR)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    return FileResponse(filepath)


# ============== INVITE LINK ENDPOINTS (v3.9.0) ==============

def generate_invite_code() -> str:
    """Generate a unique 8-character invite code."""
    import secrets
    import string
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))


@router.post("/{group_id}/invite-link", response_model=InviteLinkResponse)
async def create_or_enable_invite_link(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Create or enable invite link for a group (owner/admin only)."""
    # Check permission
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Generate invite code if not exists
    if not group.invite_code:
        # Generate unique code
        for _ in range(10):  # Max 10 attempts
            code = generate_invite_code()
            existing = await db.execute(select(Group).where(Group.invite_code == code))
            if not existing.scalar_one_or_none():
                group.invite_code = code
                break
        else:
            raise HTTPException(status_code=500, detail="Failed to generate invite code")
    
    # Enable invite link
    group.invite_link_enabled = True
    await db.commit()
    
    # Build full invite link
    # Note: In production this should use the actual domain
    invite_link = f"/join/{group.invite_code}"
    
    return InviteLinkResponse(
        invite_code=group.invite_code,
        invite_link=invite_link,
        enabled=True,
    )


@router.delete("/{group_id}/invite-link", status_code=status.HTTP_200_OK)
async def disable_invite_link(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Disable invite link for a group (owner/admin only)."""
    # Check permission
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    group.invite_link_enabled = False
    await db.commit()
    
    return {"status": "disabled"}


@router.post("/{group_id}/invite-link/reset", response_model=InviteLinkResponse)
async def reset_invite_link(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Reset (regenerate) invite link code (owner/admin only)."""
    # Check permission
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Generate new unique code
    for _ in range(10):
        code = generate_invite_code()
        existing = await db.execute(select(Group).where(Group.invite_code == code))
        if not existing.scalar_one_or_none():
            group.invite_code = code
            break
    else:
        raise HTTPException(status_code=500, detail="Failed to generate invite code")
    
    group.invite_link_enabled = True
    await db.commit()
    
    invite_link = f"/join/{group.invite_code}"
    
    return InviteLinkResponse(
        invite_code=group.invite_code,
        invite_link=invite_link,
        enabled=True,
    )


@router.get("/{group_id}/invite-link", response_model=InviteLinkResponse | None)
async def get_invite_link(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get current invite link status (owner/admin only)."""
    # Check permission
    member_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
                GroupMember.role.in_(['owner', 'admin']),
            )
        )
    )
    if not member_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    if not group.invite_code:
        return None
    
    invite_link = f"/join/{group.invite_code}"
    
    return InviteLinkResponse(
        invite_code=group.invite_code,
        invite_link=invite_link,
        enabled=group.invite_link_enabled,
    )


# ============== JOIN VIA INVITE LINK (Public endpoints) ==============

@router.get("/join/{invite_code}", response_model=GroupPublicInfo)
async def get_group_by_invite_code(
    invite_code: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get group info by invite code (for preview before joining)."""
    # Find group by invite code
    result = await db.execute(
        select(Group).where(
            and_(
                Group.invite_code == invite_code,
                Group.invite_link_enabled == True,
                Group.is_deleted == False,
            )
        )
    )
    group = result.scalar_one_or_none()
    
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or expired invite link")
    
    # Get member count
    count_result = await db.execute(
        select(func.count(GroupMember.id)).where(GroupMember.group_id == group.id)
    )
    member_count = count_result.scalar() or 0
    
    # Check if user is already a member
    member_check = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group.id,
                GroupMember.user_id == user_id,
            )
        )
    )
    is_member = member_check.scalar_one_or_none() is not None
    
    return GroupPublicInfo(
        id=group.id,
        name=group.name,
        description=group.description,
        avatar_url=group.avatar_url,
        member_count=member_count,
        is_already_member=is_member,
    )


@router.post("/join/{invite_code}", response_model=GroupResponse)
async def join_group_by_invite_code(
    invite_code: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Join a group using invite code."""
    import logging
    logger = logging.getLogger(__name__)
    
    # Find group by invite code
    result = await db.execute(
        select(Group).where(
            and_(
                Group.invite_code == invite_code,
                Group.invite_link_enabled == True,
                Group.is_deleted == False,
            )
        )
    )
    group = result.scalar_one_or_none()
    
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or expired invite link")
    
    # Check if already a member
    member_check = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group.id,
                GroupMember.user_id == user_id,
            )
        )
    )
    if member_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already a member of this group")
    
    # Add user as member (v3.11.10: subscriber for channels)
    member = GroupMember(
        group_id=group.id,
        user_id=user_id,
        role="subscriber" if group.is_channel else "member",
    )
    db.add(member)
    try:
        await db.commit()
    except IntegrityError:
        # КАО#250 (#15): concurrent join — already a member
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already a member of this group")

    # Get user info for notification
    user_info = await get_user_info(db, user_id)
    
    # Notify group members about new member
    members_result = await db.execute(
        select(GroupMember).where(GroupMember.group_id == group.id)
    )
    members = members_result.scalars().all()
    
    for m in members:
        if m.user_id != user_id:
            await ws_manager.send_to_user(
                m.user_id,
                WSMessage(
                    type=WSMessageType.NEW_MESSAGE,
                    payload={
                        "type": "member_joined",
                        "group_id": group.id,
                        "group_name": group.name,
                        "user_id": user_id,
                        "user_name": user_info["display_name"],
                        "via_invite_link": True,
                    }
                )
            )
    
    logger.info(f"User {user_id} joined group {group.id} via invite link")
    
    # Return full group response
    return await get_group(group.id, db, user_id)


# ============== ROLE MANAGEMENT ENDPOINTS (v3.9.0) ==============

@router.put("/{group_id}/members/{member_id}/role", status_code=status.HTTP_200_OK)
async def change_member_role(
    group_id: str,
    member_id: str,
    request: ChangeRoleRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Change a member's role (owner/admin only, with hierarchy rules)."""
    import logging
    logger = logging.getLogger(__name__)
    
    # Get actor's membership
    actor_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    actor = actor_result.scalar_one_or_none()
    
    if not actor:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")
    
    # Only owner and admin can change roles
    if actor.role not in ['owner', 'admin']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to change roles")
    
    # Get target member
    target_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == member_id,
            )
        )
    )
    target = target_result.scalar_one_or_none()
    
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    
    # Cannot change own role
    if member_id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change your own role")
    
    # Cannot change owner's role
    if target.role == 'owner':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot change owner's role")
    
    # Check role hierarchy - can only manage roles below your own
    if not can_manage_role(actor.role, target.role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot manage users with equal or higher role")
    
    # Admin cannot promote to admin (only owner can)
    if actor.role == 'admin' and request.role == 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can promote to admin")
    
    # Check the new role is not higher than actor's role
    if ROLE_HIERARCHY.get(request.role, 0) >= ROLE_HIERARCHY.get(actor.role, 0):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot assign role equal to or higher than your own")
    
    old_role = target.role
    target.role = request.role
    await db.commit()
    
    # Get user info for notification
    target_info = await get_user_info(db, member_id)
    actor_info = await get_user_info(db, user_id)
    
    # Notify the user whose role was changed
    await ws_manager.send_to_user(
        member_id,
        WSMessage(
            type=WSMessageType.NEW_MESSAGE,
            payload={
                "type": "role_changed",
                "group_id": group_id,
                "old_role": old_role,
                "new_role": request.role,
                "changed_by": actor_info["display_name"],
            }
        )
    )
    
    logger.info(f"User {member_id} role changed from {old_role} to {request.role} in group {group_id} by {user_id}")
    
    return {
        "user_id": member_id,
        "username": target_info["username"],
        "display_name": target_info["display_name"],
        "old_role": old_role,
        "new_role": request.role,
    }


@router.post("/{group_id}/transfer-ownership", status_code=status.HTTP_200_OK)
async def transfer_group_ownership(
    group_id: str,
    request: Request,
    new_owner_id: str = Query(..., description="User ID of the new owner"),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """
    Transfer group ownership to another member (owner only).
    v3.11.9: Requires step-up verification if user has registered passkeys.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # v3.11.9: Enforce step-up if user has passkeys (not optional anymore)
    from app.api.webauthn_api import require_step_up_if_passkeys
    await require_step_up_if_passkeys(request, user_id, db)
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    
    if not group or group.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    # Only current owner can transfer ownership
    if group.created_by != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can transfer ownership")
    
    # Get current owner's membership
    owner_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == user_id,
            )
        )
    )
    owner_member = owner_result.scalar_one_or_none()
    
    # Get new owner's membership
    new_owner_result = await db.execute(
        select(GroupMember).where(
            and_(
                GroupMember.group_id == group_id,
                GroupMember.user_id == new_owner_id,
            )
        )
    )
    new_owner_member = new_owner_result.scalar_one_or_none()
    
    if not new_owner_member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="New owner must be a member of the group")
    
    if new_owner_id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are already the owner")
    
    # Update roles
    owner_member.role = "admin"  # Old owner becomes admin
    new_owner_member.role = "owner"  # New member becomes owner
    group.created_by = new_owner_id  # Update group created_by
    
    await db.commit()
    
    # Get info for notifications
    old_owner_info = await get_user_info(db, user_id)
    new_owner_info = await get_user_info(db, new_owner_id)
    
    # Notify new owner
    await ws_manager.send_to_user(
        new_owner_id,
        WSMessage(
            type=WSMessageType.NEW_MESSAGE,
            payload={
                "type": "ownership_transferred",
                "group_id": group_id,
                "group_name": group.name,
                "previous_owner": old_owner_info["display_name"],
            }
        )
    )
    
    # Notify all other members
    members_result = await db.execute(
        select(GroupMember).where(GroupMember.group_id == group_id)
    )
    for member in members_result.scalars().all():
        if member.user_id not in [user_id, new_owner_id]:
            await ws_manager.send_to_user(
                member.user_id,
                WSMessage(
                    type=WSMessageType.NEW_MESSAGE,
                    payload={
                        "type": "group_owner_changed",
                        "group_id": group_id,
                        "group_name": group.name,
                        "new_owner": new_owner_info["display_name"],
                    }
                )
            )
    
    logger.info(f"Group {group_id} ownership transferred from {user_id} to {new_owner_id}")
    
    return {
        "status": "transferred",
        "new_owner_id": new_owner_id,
        "new_owner_name": new_owner_info["display_name"],
    }
