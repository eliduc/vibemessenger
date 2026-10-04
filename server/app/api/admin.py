"""
Admin API endpoints for VibeMessenger.
Version: 3.3

New in 3.3:
- Added: PQXDH (Post-Quantum) admin endpoints:
  - GET /admin/e2ee/pqxdh/stats — PQ vs classic bundle counts
  - GET /admin/e2ee/pqxdh/users — per-user PQ migration status
  - GET /admin/e2ee/pqxdh/users/{id}/bundle — detailed bundle info
  - POST /admin/e2ee/pqxdh/force-rotation/{id} — force key reset for PQ re-enrollment
- Added: pqxdh section in /admin/stats (pq_bundles, total_bundles, classic_bundles)
- Added: e2ee section in /admin/stats (users_with_keys count)

New in 3.2:
- Added: has_passkeys/passkey_count fields to UserInfo (WebAuthn v3.10.0)
- Added: GET /admin/users/{user_id}/webauthn - list user's passkeys
- Added: DELETE /admin/users/{user_id}/webauthn - reset all passkeys for a user
- Added: webauthn section in /admin/stats (users_with_passkeys count)

New in 3.1:
- Added: POST /admin/messages/send - send plaintext message to user from admin

New in 3.0:
- Fixed: DELETE /admin/sessions/{user_id} now also revokes all refresh tokens

New in 2.9:
- Added: DELETE /admin/messages/batch - batch delete messages by ID (up to 1000)

New in 2.8:
- Fixed: E2EE stats endpoint - was trying to import non-existent models
- Fixed: Users needing rotation endpoint - same import issue
- Note: PreKeys stored as JSON in KeyBundle.one_time_prekeys, not separate table
- Note: E2EE sessions stored client-side in IndexedDB (Signal Protocol)

New in 2.7:
- Added: POST /admin/notify/users - send notification to multiple users
- Added: POST /admin/notify/user/{user_id} - send notification to single user

New in 2.6:
- Added: include_deleted parameter to GET /admin/messages (default: false)
- Added: deleted_for_sender and deleted_for_recipient fields in messages response
- Added: recipient_name field in messages response

New in 2.5:
- Fixed: GET /admin/groups now excludes deleted groups (is_deleted=False filter)
- Fixed: DELETE /admin/groups/batch now only selects non-deleted groups

New in 2.4:
- Added: DELETE /admin/groups/batch for batch group deletion (up to 100 groups)

New in 2.3:
- Added: DELETE /admin/users/batch for batch user deletion (up to 100 users)

New in 2.2:
- Fixed: DELETE /polls/batch now properly parses JSON body with Body(...)
- Fixed: Replaced bare except: with except Exception: (5 places)

New in 2.1:
- Batch operations for polls: DELETE /admin/polls/batch, POST /admin/polls/batch/close
- Up to 1000 polls per batch request

New in 2.0:
- Security stats endpoints (failed logins, key verification, key backups)
- E2EE statistics (key bundles, prekeys, sessions)
- Extended dashboard stats (websocket, uptime, version, errors)
- User extensions (last activity, force logout, reset 2FA)
- Messages management (search metadata, stats by type, spam deletion)
- Server health and version info
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body, Request  # КАО#378: the admin delete needs it for the audit row (ip/user-agent)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, or_, func, distinct
from pydantic import BaseModel, Field
from typing import Optional, List
import subprocess
import os
import glob
import shutil
import tarfile
import json
import time
import psutil
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.models.user import User, RefreshToken, WebAuthnCredential, KeyBundle
from app.api.auth import get_current_user
from app.services.websocket_manager import ws_manager
from app.models.message import WSMessage, WSMessageType, Message
from app.models.audit import AuditLog, AuditEventType, AuditSeverity

router = APIRouter(prefix="/admin", tags=["Admin"])

# Server start time for uptime calculation
SERVER_START_TIME = time.time()
APP_VERSION = "3.6.5"


# ==================== MODELS ====================

class UserPermissions(BaseModel):
    can_send_text: bool = True
    can_send_files: bool = True
    can_send_voice: bool = True
    can_call: bool = True
    is_blocked: bool = False


class UserInfo(BaseModel):
    id: str
    username: str
    display_name: str
    can_send_text: bool
    can_send_files: bool
    can_send_voice: bool
    can_call: bool
    is_blocked: bool
    is_admin: bool
    last_seen: Optional[datetime] = None
    session_count: int = 0
    has_totp: bool = False
    has_passkeys: bool = False      # v3.2: WebAuthn passkeys registered
    passkey_count: int = 0          # v3.2: Number of registered passkeys

    class Config:
        from_attributes = True


class GroupMemberInfo(BaseModel):
    user_id: str
    username: str
    display_name: str
    role: str
    
    class Config:
        from_attributes = True


class GroupInfo(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_by: str
    creator_name: str
    member_count: int
    is_deleted: bool
    
    class Config:
        from_attributes = True


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Require admin privileges."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# ==================== USER MANAGEMENT ====================

@router.get("/users", response_model=list[UserInfo])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get list of all users with their permissions and extended info."""
    result = await db.execute(select(User).order_by(User.display_name))
    users = result.scalars().all()
    
    # v3.2: Get passkey counts for all users in one query
    passkey_counts = {}
    try:
        pk_result = await db.execute(
            select(WebAuthnCredential.user_id, func.count(WebAuthnCredential.id))
            .group_by(WebAuthnCredential.user_id)
        )
        for user_id, count in pk_result.all():
            passkey_counts[user_id] = count
    except Exception:
        pass  # Table may not exist on older installs
    
    user_list = []
    for u in users:
        # Get session count for this user
        try:
            session_count = len(ws_manager._connections.get(u.id, []))
        except Exception:
            session_count = 0
        
        pk_count = passkey_counts.get(u.id, 0)
        
        user_list.append(UserInfo(
            id=u.id,
            username=u.username,
            display_name=u.display_name or u.username,
            can_send_text=u.can_send_text,
            can_send_files=u.can_send_files,
            can_send_voice=u.can_send_voice,
            can_call=u.can_call,
            is_blocked=u.is_blocked,
            is_admin=u.is_admin,
            last_seen=getattr(u, 'last_seen', None),
            session_count=session_count,
            has_totp=getattr(u, 'totp_secret', None) is not None,
            has_passkeys=pk_count > 0,
            passkey_count=pk_count,
        ))
    
    return user_list


@router.get("/users/{user_id}", response_model=UserInfo)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get user details."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        session_count = len(ws_manager._connections.get(user_id, []))
    except Exception:
        session_count = 0
    
    # v3.2: Get passkey count
    pk_count = 0
    try:
        pk_result = await db.execute(
            select(func.count(WebAuthnCredential.id))
            .where(WebAuthnCredential.user_id == user_id)
        )
        pk_count = pk_result.scalar() or 0
    except Exception:
        pass
    
    return UserInfo(
        id=user.id,
        username=user.username,
        display_name=user.display_name or user.username,
        can_send_text=user.can_send_text,
        can_send_files=user.can_send_files,
        can_send_voice=user.can_send_voice,
        can_call=user.can_call,
        is_blocked=user.is_blocked,
        is_admin=user.is_admin,
        last_seen=getattr(user, 'last_seen', None),
        session_count=session_count,
        has_totp=getattr(user, 'totp_secret', None) is not None,
        has_passkeys=pk_count > 0,
        passkey_count=pk_count,
    )


@router.put("/users/{user_id}/permissions")
async def update_permissions(
    user_id: str,
    permissions: UserPermissions,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Update user permissions."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent blocking admins
    if user.is_admin and permissions.is_blocked:
        raise HTTPException(status_code=400, detail="Cannot block admin users")
    
    user.can_send_text = permissions.can_send_text
    user.can_send_files = permissions.can_send_files
    user.can_send_voice = permissions.can_send_voice
    user.can_call = permissions.can_call
    user.is_blocked = permissions.is_blocked

    # КАО#009 (SER#23): revoke all active sessions when blocking a user
    if permissions.is_blocked:
        revoke_res = await db.execute(
            select(RefreshToken).where(
                and_(RefreshToken.user_id == user.id, RefreshToken.is_revoked == False)
            )
        )
        for _t in revoke_res.scalars().all():
            _t.is_revoked = True

    await db.commit()

    return {"status": "ok", "message": "Permissions updated"}


class BatchUsersRequest(BaseModel):
    """Request model for batch user operations."""
    user_ids: List[str]


# КАО#378: `DELETE /admin/users/batch` was REMOVED, not repaired.
# It ran `await db.delete(user)` in a loop for up to 100 users - the same silent corruption as the single
# route, multiplied by 100 - and nothing calls it: the web client contains no /admin references at all, and
# this deployment has exactly one admin. Repairing it would have meant driving the real purge from inside a
# loop, which introduces hazards the single route does not have: the purge owns its transaction and its
# fail-clean path rolls back, and rollback() expires the whole identity map, so one failure mid-batch would
# break every later iteration; and when two members of the same batch are the only two members of a group,
# iteration order alone would decide whether that group survives. Deleting users one at a time has neither
# problem.

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a user, through the SAME purge the self-service endpoint uses.

    КАО#378: this used to be a bare `await db.delete(user)`. That does NOT fail - key_bundles,
    refresh_tokens and webauthn_credentials cascade through their ORM relationships, and
    push_subscriptions/file_metadata are ON DELETE CASCADE - so it SUCCEEDED on every call and silently
    corrupted, because ten further tables reference users with no foreign key at all. Measured on the
    production database: 124 messages and 19 groups pointed at users that no longer existed, while orphan
    key_bundles / refresh_tokens / webauthn / file_metadata were all 0 - exactly the signature of a delete
    that cascaded the FK-backed tables and left everything else behind. It also freed the username instantly
    (so the other party history lost its sender entirely instead of showing a deleted account) and orphaned
    the uploaded bytes for ever, because the file_metadata rows cascaded away and nothing unlinks a file you
    can no longer find.
    """
    from app.services.account_deletion import purge_user_account, AccountDeletionError, AlreadyDeleted

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_admin:
        raise HTTPException(status_code=400, detail="Cannot delete admin users")

    # Snapshot everything needed BEFORE the call: purge_user_account owns the transaction and its fail-clean
    # path calls rollback(), which expires every object in the identity map regardless of expire_on_commit -
    # reading user.* or admin.* afterwards would raise MissingGreenlet.
    target_username = user.username
    actor_username = admin.username
    actor_id = admin.id

    try:
        outcome = await purge_user_account(
            db, user_id,
            actor_id=actor_id,
            actor_username=actor_username,
            request=request,
            reason=f"account deleted by admin {actor_username}",
        )
    except AlreadyDeleted:
        return {"status": "ok", "message": "User was already deleted", "already_deleted": True}
    except AccountDeletionError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return {
        "status": "ok",
        "message": "User deleted",
        "deleted_username": target_username,
        "tombstone_username": outcome["tombstone_username"],
        "groups_transferred": outcome["groups_transferred"],
        "groups_deleted": outcome["groups_deleted"],
        "files_removed": outcome["files_removed"],
    }


@router.post("/users/{user_id}/force-logout")
async def force_logout_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Force logout all sessions for a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Disconnect all WebSocket sessions
    count = await ws_manager.disconnect_user(user_id, "Forced logout by administrator")
    
    # Invalidate all refresh tokens if applicable
    # This depends on your token storage implementation
    
    return {
        "status": "ok", 
        "message": f"User logged out from {count} session(s)",
        "sessions_closed": count
    }


@router.delete("/users/{user_id}/totp")
async def reset_user_totp(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Reset 2FA (TOTP) for a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if user has TOTP enabled
    if not getattr(user, 'totp_secret', None):
        raise HTTPException(status_code=400, detail="User does not have 2FA enabled")
    
    # Reset TOTP
    user.totp_secret = None
    user.totp_enabled = False
    await db.commit()
    
    # Log this action
    await log_audit_event(
        db, 
        AuditEventType.ADMIN_ACTION if hasattr(AuditEventType, 'ADMIN_ACTION') else "admin_action",
        AuditSeverity.WARNING if hasattr(AuditSeverity, 'WARNING') else "warning",
        admin.id,
        f"Reset 2FA for user {user.username}",
        target_user_id=user_id
    )
    
    return {"status": "ok", "message": "2FA reset successfully"}


# ==================== WEBAUTHN / PASSKEYS (v3.2) ====================

@router.get("/users/{user_id}/webauthn")
async def get_user_passkeys(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get list of passkeys (WebAuthn credentials) for a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    result = await db.execute(
        select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)
    )
    creds = result.scalars().all()
    
    return [
        {
            "id": c.id,
            "credential_id": c.credential_id,
            "device_name": c.device_name,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in creds
    ]


@router.delete("/users/{user_id}/webauthn")
async def reset_user_passkeys(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete ALL passkeys (WebAuthn credentials) for a user. Admin reset action."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Count before deleting
    count_result = await db.execute(
        select(func.count(WebAuthnCredential.id))
        .where(WebAuthnCredential.user_id == user_id)
    )
    count = count_result.scalar() or 0
    
    if count == 0:
        raise HTTPException(status_code=400, detail="User does not have any passkeys registered")
    
    # Delete all passkeys
    await db.execute(
        WebAuthnCredential.__table__.delete().where(WebAuthnCredential.user_id == user_id)
    )
    await db.commit()
    
    # Log this action
    await log_audit_event(
        db,
        AuditEventType.ADMIN_ACTION if hasattr(AuditEventType, 'ADMIN_ACTION') else "admin_action",
        AuditSeverity.WARNING if hasattr(AuditSeverity, 'WARNING') else "warning",
        admin.id,
        f"Reset {count} passkey(s) for user {user.username}",
        target_user_id=user_id
    )
    
    return {"status": "ok", "message": f"{count} passkey(s) deleted", "deleted_count": count}


@router.delete("/users/{user_id}/webauthn/{credential_id}")
async def delete_user_passkey(
    user_id: str,
    credential_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a specific passkey for a user."""
    result = await db.execute(
        select(WebAuthnCredential).where(
            and_(WebAuthnCredential.user_id == user_id, WebAuthnCredential.id == credential_id)
        )
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="Passkey not found")
    
    device_name = cred.device_name
    await db.delete(cred)
    await db.commit()
    
    # Get username for audit log
    user_result = await db.execute(select(User.username).where(User.id == user_id))
    username = user_result.scalar() or user_id
    
    await log_audit_event(
        db,
        AuditEventType.ADMIN_ACTION if hasattr(AuditEventType, 'ADMIN_ACTION') else "admin_action",
        AuditSeverity.WARNING if hasattr(AuditSeverity, 'WARNING') else "warning",
        admin.id,
        f"Deleted passkey '{device_name}' for user {username}",
        target_user_id=user_id
    )
    
    return {"status": "ok", "message": f"Passkey '{device_name}' deleted"}


# ==================== GROUP MANAGEMENT ====================

@router.get("/groups")
async def list_groups(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get list of all groups (excluding deleted)."""
    from app.models.group import Group, GroupMember
    
    # Get all non-deleted groups with member count
    result = await db.execute(
        select(
            Group,
            func.count(GroupMember.user_id).label('member_count')
        )
        .outerjoin(GroupMember, Group.id == GroupMember.group_id)
        .where(Group.is_deleted == False)
        .group_by(Group.id)
        .order_by(Group.name)
    )
    
    groups = []
    for group, member_count in result.all():
        # Get creator info
        creator_result = await db.execute(select(User).where(User.id == group.created_by))
        creator = creator_result.scalar_one_or_none()
        creator_name = creator.display_name if creator else "Unknown"
        
        groups.append({
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_by": group.created_by,
            "creator_name": creator_name,
            "member_count": member_count,
            "is_deleted": group.is_deleted,
        })
    
    return groups


@router.get("/groups/{group_id}/members")
async def get_group_members(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get members of a specific group."""
    from app.models.group import Group, GroupMember
    
    # Verify group exists
    group_result = await db.execute(select(Group).where(Group.id == group_id))
    group = group_result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Get members
    result = await db.execute(
        select(GroupMember, User)
        .join(User, GroupMember.user_id == User.id)
        .where(GroupMember.group_id == group_id)
    )
    
    members = []
    for member, user in result.all():
        members.append({
            "user_id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
            "role": member.role.value if hasattr(member.role, 'value') else member.role,
        })
    
    return {
        "group": {
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "created_by": group.created_by,
            "is_deleted": group.is_deleted,
        },
        "members": members,
    }


class BatchGroupsRequest(BaseModel):
    """Request model for batch group operations."""
    group_ids: List[str]


@router.delete("/groups/batch")
async def admin_batch_delete_groups(
    request: BatchGroupsRequest = Body(...),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete multiple groups in one request (soft delete)."""
    from app.models.group import Group, GroupMember
    
    if not request.group_ids:
        raise HTTPException(status_code=400, detail="No group IDs provided")
    
    if len(request.group_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 groups per batch")
    
    # Get all non-deleted groups
    result = await db.execute(
        select(Group).where(
            Group.id.in_(request.group_ids),
            Group.is_deleted == False
        )
    )
    groups = result.scalars().all()
    
    deleted_count = 0
    not_found = len(request.group_ids) - len(groups)
    notified_users = set()
    
    for group in groups:
        # Get members to notify
        members_result = await db.execute(
            select(GroupMember.user_id).where(GroupMember.group_id == group.id)
        )
        member_ids = [m[0] for m in members_result.all()]
        
        # Soft delete
        group.is_deleted = True
        deleted_count += 1
        
        # Notify members
        for member_id in member_ids:
            notified_users.add(member_id)
            await ws_manager.send_to_user(
                member_id,
                WSMessage(
                    type=WSMessageType.NEW_MESSAGE,
                    payload={
                        "type": "admin_group_deleted",
                        "group_id": group.id,
                        "group_name": group.name,
                        "message": f"Group '{group.name}' was deleted by administrator",
                    }
                )
            )
    
    await db.commit()
    
    return {
        "status": "ok",
        "deleted": deleted_count,
        "not_found": not_found,
        "users_notified": len(notified_users),
        "total_requested": len(request.group_ids)
    }


@router.delete("/groups/{group_id}")
async def admin_delete_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a group (admin action). Notifies all members."""
    from app.models.group import Group, GroupMember
    
    # Get group
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Get all members to notify
    members_result = await db.execute(
        select(GroupMember.user_id).where(GroupMember.group_id == group_id)
    )
    member_ids = [m[0] for m in members_result.all()]
    
    group_name = group.name
    
    # Soft delete the group
    group.is_deleted = True
    await db.commit()
    
    # Notify all members
    for member_id in member_ids:
        await ws_manager.send_to_user(
            member_id,
            WSMessage(
                type=WSMessageType.NEW_MESSAGE,
                payload={
                    "type": "admin_group_deleted",
                    "group_id": group_id,
                    "group_name": group_name,
                    "message": f"Group '{group_name}' was deleted by administrator",
                }
            )
        )
    
    return {"status": "ok", "message": f"Group deleted, {len(member_ids)} members notified"}


@router.delete("/groups/{group_id}/members/{user_id}")
async def admin_remove_member(
    group_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Remove a member from a group (admin action). Notifies the removed member."""
    from app.models.group import Group, GroupMember
    
    # Get group
    group_result = await db.execute(select(Group).where(Group.id == group_id))
    group = group_result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Get membership
    member_result = await db.execute(
        select(GroupMember).where(
            GroupMember.group_id == group_id,
            GroupMember.user_id == user_id,
        )
    )
    member = member_result.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="User is not a member of this group")
    
    # Remove member
    await db.delete(member)
    await db.commit()
    
    # Notify the removed user
    await ws_manager.send_to_user(
        user_id,
        WSMessage(
            type=WSMessageType.NEW_MESSAGE,
            payload={
                "type": "admin_removed_from_group",
                "group_id": group_id,
                "group_name": group.name,
                "message": f"You were removed from group '{group.name}' by administrator",
            }
        )
    )
    
    return {"status": "ok", "message": "Member removed and notified"}


# ==================== SESSION MANAGEMENT ====================

class SessionInfo(BaseModel):
    user_id: str
    username: str
    display_name: str
    device_id: Optional[str]
    connected_at: str
    last_ping: str


@router.get("/sessions")
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get list of all active WebSocket sessions."""
    sessions = ws_manager.get_all_sessions()
    
    # Enrich with user info
    enriched_sessions = []
    user_cache = {}
    
    for session in sessions:
        user_id = session["user_id"]
        
        # Cache user lookups
        if user_id not in user_cache:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            user_cache[user_id] = user
        
        user = user_cache[user_id]
        if user:
            enriched_sessions.append({
                "user_id": user_id,
                "username": user.username,
                "display_name": user.display_name or user.username,
                "device_id": session.get("device_id"),
                "connected_at": session.get("connected_at"),
                "last_ping": session.get("last_ping"),
                "ip_address": session.get("ip_address", "-"),
                "user_agent": session.get("user_agent", "-"),
            })
    
    return {
        "total": len(enriched_sessions),
        "sessions": enriched_sessions
    }


@router.delete("/sessions/{user_id}")
async def disconnect_user_sessions(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Disconnect all sessions for a specific user and revoke their tokens."""
    # v3.0: Also revoke all refresh tokens for this user
    result = await db.execute(
        select(RefreshToken).where(
            and_(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            )
        )
    )
    tokens = result.scalars().all()
    tokens_revoked = 0
    for token in tokens:
        token.is_revoked = True
        tokens_revoked += 1
    if tokens_revoked > 0:
        await db.commit()
    
    # Disconnect WebSocket sessions
    ws_count = await ws_manager.disconnect_user(user_id, "Disconnected by administrator")
    
    if ws_count == 0 and tokens_revoked == 0:
        raise HTTPException(status_code=404, detail="No active sessions found for this user")
    
    return {"status": "ok", "message": f"Disconnected {ws_count} WebSocket(s), revoked {tokens_revoked} token(s)", "ws_count": ws_count, "tokens_revoked": tokens_revoked}


@router.delete("/sessions/{user_id}/{device_id}")
async def disconnect_specific_session(
    user_id: str,
    device_id: str,
    admin: User = Depends(require_admin),
):
    """Disconnect a specific session by user_id and device_id."""
    # Handle 'null' string as None
    actual_device_id = None if device_id == "null" else device_id
    
    success = await ws_manager.disconnect_session(user_id, actual_device_id, "Disconnected by administrator")
    
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {"status": "ok", "message": "Session disconnected"}


# ==================== NOTIFICATIONS ====================

class NotifyUsersRequest(BaseModel):
    """Request to send notification to users."""
    user_ids: list[str]
    message: str = Field(..., min_length=1, max_length=1000)
    title: str = Field(default="Admin Notification", max_length=100)


@router.post("/notify/users")
async def notify_users(
    request: NotifyUsersRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Send notification to specific users via WebSocket."""
    if not request.user_ids:
        raise HTTPException(status_code=400, detail="No users specified")
    
    if len(request.user_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 users per request")
    
    sent_count = 0
    failed_count = 0
    
    for user_id in request.user_ids:
        try:
            await ws_manager.send_to_user(
                user_id,
                WSMessage(
                    type=WSMessageType.NEW_MESSAGE,
                    payload={
                        "type": "admin_notification",
                        "title": request.title,
                        "message": request.message,
                        "from": "Administrator",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )
            )
            sent_count += 1
        except Exception:
            failed_count += 1
    
    # Log the action
    await log_audit_event(
        db=db,
        event_type="admin_notify_users",
        severity="info",
        user_id=admin.id,
        details=f"Sent notification to {sent_count} users (failed: {failed_count})"
    )
    
    return {
        "status": "ok",
        "message": f"Notification sent to {sent_count} users",
        "sent": sent_count,
        "failed": failed_count,
        "total": len(request.user_ids)
    }


@router.post("/notify/user/{user_id}")
async def notify_single_user(
    user_id: str,
    message: str = Body(..., embed=True, min_length=1, max_length=1000),
    title: str = Body(default="Admin Notification", embed=True, max_length=100),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Send notification to a single user via WebSocket."""
    # Verify user exists
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    try:
        await ws_manager.send_to_user(
            user_id,
            WSMessage(
                type=WSMessageType.NEW_MESSAGE,
                payload={
                    "type": "admin_notification",
                    "title": title,
                    "message": message,
                    "from": "Administrator",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send notification: {str(e)}")
    
    # Log the action
    await log_audit_event(
        db=db,
        event_type="admin_notify_user",
        severity="info",
        user_id=admin.id,
        details=f"Sent notification to user {user.username}",
        target_user_id=user_id
    )
    
    return {"status": "ok", "message": f"Notification sent to {user.username}"}


# ==================== SECURITY STATS ====================

@router.get("/security/stats")
async def get_security_stats(
    days: int = Query(7, ge=1, le=90),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get security statistics."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Failed login attempts
    failed_logins_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            AuditLog.created_at >= start_date,
            AuditLog.event_type == "login_failed"
        )
    )
    failed_logins = failed_logins_result.scalar() or 0
    
    # Blocked users count
    blocked_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_blocked == True)
    )
    blocked_users = blocked_users_result.scalar() or 0
    
    # Users blocked in this period (from audit)
    users_blocked_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            AuditLog.created_at >= start_date,
            AuditLog.event_type == "user_blocked"
        )
    )
    users_blocked_period = users_blocked_result.scalar() or 0
    
    # Suspicious IPs (multiple failed logins from same IP)
    suspicious_ips_result = await db.execute(
        select(AuditLog.ip_address, func.count(AuditLog.id).label('count'))
        .where(
            AuditLog.created_at >= start_date,
            AuditLog.event_type == "login_failed"
        )
        .group_by(AuditLog.ip_address)
        .having(func.count(AuditLog.id) >= 5)
    )
    suspicious_ips = [{"ip": row[0], "attempts": row[1]} for row in suspicious_ips_result.all()]
    
    # Password changes in period
    password_changes_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(
            AuditLog.created_at >= start_date,
            AuditLog.event_type == "password_changed"
        )
    )
    password_changes = password_changes_result.scalar() or 0
    
    # 2FA enabled/disabled
    totp_enabled_result = await db.execute(
        select(func.count(User.id))
        .where(User.totp_enabled == True)
    )
    totp_enabled = totp_enabled_result.scalar() or 0
    
    return {
        "period_days": days,
        "failed_logins": failed_logins,
        "blocked_users": {
            "total": blocked_users,
            "blocked_in_period": users_blocked_period
        },
        "suspicious_ips": suspicious_ips,
        "password_changes": password_changes,
        "totp": {
            "enabled_users": totp_enabled
        }
    }


@router.get("/security/key-verification")
async def get_key_verification_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get key verification statistics."""
    try:
        from app.models.keys import KeyVerification
        
        # Total verifications
        total_result = await db.execute(select(func.count(KeyVerification.id)))
        total = total_result.scalar() or 0
        
        # Verified pairs
        verified_result = await db.execute(
            select(func.count(KeyVerification.id))
            .where(KeyVerification.verified == True)
        )
        verified = verified_result.scalar() or 0
        
        # Recent verifications (last 7 days)
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_result = await db.execute(
            select(func.count(KeyVerification.id))
            .where(KeyVerification.verified_at >= week_ago)
        )
        recent = recent_result.scalar() or 0
        
        return {
            "total_pairs": total,
            "verified_pairs": verified,
            "unverified_pairs": total - verified,
            "recent_verifications_7d": recent
        }
    except ImportError:
        return {
            "total_pairs": 0,
            "verified_pairs": 0,
            "unverified_pairs": 0,
            "recent_verifications_7d": 0,
            "note": "Key verification model not available"
        }


@router.get("/security/key-backups")
async def get_key_backup_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get key backup statistics."""
    try:
        from app.models.keys import KeyBackup
        
        # Total users with backups
        users_with_backup_result = await db.execute(
            select(func.count(distinct(KeyBackup.user_id)))
        )
        users_with_backup = users_with_backup_result.scalar() or 0
        
        # Total users
        total_users_result = await db.execute(select(func.count(User.id)))
        total_users = total_users_result.scalar() or 0
        
        # Recent backups (last 7 days)
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_result = await db.execute(
            select(func.count(KeyBackup.id))
            .where(KeyBackup.created_at >= week_ago)
        )
        recent = recent_result.scalar() or 0
        
        return {
            "users_with_backup": users_with_backup,
            "total_users": total_users,
            "backup_percentage": round((users_with_backup / total_users * 100) if total_users > 0 else 0, 1),
            "recent_backups_7d": recent
        }
    except ImportError:
        # Return estimate based on audit logs if model not available
        return {
            "users_with_backup": 0,
            "total_users": 0,
            "backup_percentage": 0,
            "recent_backups_7d": 0,
            "note": "Key backup model not available"
        }


# ==================== E2EE STATS ====================

@router.get("/e2ee/stats")
async def get_e2ee_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get End-to-End Encryption statistics.
    
    Note: E2EE sessions are stored client-side in IndexedDB (Signal Protocol Double Ratchet),
    so we cannot track them server-side. PreKeys are stored as JSON in KeyBundle.one_time_prekeys.
    """
    from app.models.user import KeyBundle
    
    stats = {
        "key_bundles": {"total": 0, "with_signed_prekey": 0},
        "prekeys": {"total": 0, "available": 0, "low_count_users": 0},
        "sessions": {"total": 0, "active": 0, "note": "E2EE sessions stored client-side"},
        "identity_keys": {"total": 0}
    }
    
    # Key bundles count
    bundles_result = await db.execute(select(func.count(KeyBundle.id)))
    stats["key_bundles"]["total"] = bundles_result.scalar() or 0
    
    # With signed prekey (should be all of them)
    signed_result = await db.execute(
        select(func.count(KeyBundle.id))
        .where(KeyBundle.signed_prekey_id.isnot(None))
    )
    stats["key_bundles"]["with_signed_prekey"] = signed_result.scalar() or 0
    
    # Identity keys = key bundles (each bundle has one identity key)
    stats["identity_keys"]["total"] = stats["key_bundles"]["total"]
    
    # PreKeys - stored as JSON in one_time_prekeys field
    # Need to fetch all bundles and parse JSON
    bundles_for_prekeys = await db.execute(
        select(KeyBundle.user_id, KeyBundle.one_time_prekeys)
    )
    
    total_prekeys = 0
    low_count_users = 0
    
    for row in bundles_for_prekeys.all():
        try:
            prekeys_json = row.one_time_prekeys or "[]"
            prekeys_list = json.loads(prekeys_json) if prekeys_json else []
            prekey_count = len(prekeys_list)
            total_prekeys += prekey_count
            
            if prekey_count < 10:
                low_count_users += 1
        except (json.JSONDecodeError, TypeError):
            low_count_users += 1  # Malformed = treat as low
    
    stats["prekeys"]["total"] = total_prekeys
    stats["prekeys"]["available"] = total_prekeys  # All stored prekeys are available
    stats["prekeys"]["low_count_users"] = low_count_users
    
    return stats


@router.get("/e2ee/users-needing-rotation")
async def get_users_needing_key_rotation(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get users who need key rotation (low prekeys or old signed prekey)."""
    from app.models.user import KeyBundle
    
    users_needing_rotation = []
    
    # Get all key bundles with user info
    bundles_result = await db.execute(
        select(KeyBundle, User)
        .join(User, KeyBundle.user_id == User.id)
    )
    
    month_ago = datetime.now(timezone.utc) - timedelta(days=30)
    
    for bundle, user in bundles_result.all():
        reasons = []
        details = {}
        
        # Check low prekey count
        try:
            prekeys_json = bundle.one_time_prekeys or "[]"
            prekeys_list = json.loads(prekeys_json) if prekeys_json else []
            prekey_count = len(prekeys_list)
            
            if prekey_count < 10:
                reasons.append("low_prekeys")
                details["prekey_count"] = prekey_count
        except (json.JSONDecodeError, TypeError):
            reasons.append("malformed_prekeys")
            details["prekey_count"] = 0
        
        # Check old signed prekey
        if bundle.signed_prekey_created_at:
            if bundle.signed_prekey_created_at < month_ago:
                reasons.append("old_signed_prekey")
                details["signed_prekey_age_days"] = (datetime.now(timezone.utc) - bundle.signed_prekey_created_at).days
        
        if reasons:
            users_needing_rotation.append({
                "user_id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "reason": ", ".join(reasons),
                "details": details
            })
    
    return {
        "total": len(users_needing_rotation),
        "users": users_needing_rotation
    }


# ==================== PQXDH (v3.3: Post-Quantum Cryptography) ====================

@router.get("/e2ee/pqxdh/stats")
async def get_pqxdh_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get PQXDH migration statistics.
    
    Returns counts of users with PQ bundles (ML-KEM-768 + X25519),
    classic X3DH bundles, and users without any key bundle.
    """
    # Total bundles
    total_result = await db.execute(select(func.count(KeyBundle.id)))
    total_bundles = total_result.scalar() or 0
    
    # Bundles with PQ key (pq_kem_public_key IS NOT NULL and not empty)
    pq_result = await db.execute(
        select(func.count(KeyBundle.id)).where(
            and_(
                KeyBundle.pq_kem_public_key.isnot(None),
                KeyBundle.pq_kem_public_key != ""
            )
        )
    )
    pq_bundles = pq_result.scalar() or 0
    
    # Classic bundles = have bundle but no PQ key
    classic_bundles = total_bundles - pq_bundles
    
    # Total active users
    total_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_active == True)
    )
    total_users = total_users_result.scalar() or 0
    
    # Users with any bundle
    users_with_bundles_result = await db.execute(
        select(func.count(distinct(KeyBundle.user_id)))
    )
    users_with_bundles = users_with_bundles_result.scalar() or 0
    
    no_bundle = max(0, total_users - users_with_bundles)
    
    return {
        "pq_bundles": pq_bundles,
        "classic_bundles": classic_bundles,
        "total_bundles": total_bundles,
        "no_bundle": no_bundle,
        "total_users": total_users
    }


@router.get("/e2ee/pqxdh/users")
async def get_pqxdh_users(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get per-user PQ key status for PQXDH migration tracking."""
    # Get all non-deleted users
    users_result = await db.execute(
        select(User).where(User.is_active == True).order_by(User.username)
    )
    users = users_result.scalars().all()
    
    # Pre-load all bundles indexed by user_id
    bundles_result = await db.execute(select(KeyBundle))
    bundles_by_user = {}
    for b in bundles_result.scalars().all():
        bundles_by_user[b.user_id] = b
    
    result = []
    for user in users:
        bundle = bundles_by_user.get(user.id)
        
        user_data = {
            "user_id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
            "has_bundle": bundle is not None,
            "has_pq_key": False,
            "prekeys_remaining": 0,
            "signed_prekey_id": None,
            "signed_prekey_age_days": 0,
        }
        
        if bundle:
            has_pq = bool(
                bundle.pq_kem_public_key
                and bundle.pq_kem_public_key.strip()
            )
            user_data["has_pq_key"] = has_pq
            user_data["signed_prekey_id"] = bundle.signed_prekey_id
            
            # Count prekeys
            try:
                prekeys = json.loads(bundle.one_time_prekeys or "[]")
                user_data["prekeys_remaining"] = len(prekeys)
            except (json.JSONDecodeError, TypeError):
                user_data["prekeys_remaining"] = 0
            
            # Signed prekey age
            if hasattr(bundle, 'signed_prekey_created_at') and bundle.signed_prekey_created_at:
                age = datetime.now(timezone.utc) - bundle.signed_prekey_created_at
                user_data["signed_prekey_age_days"] = age.days
        
        result.append(user_data)
    
    return {"users": result}


@router.get("/e2ee/pqxdh/users/{user_id}/bundle")
async def get_pqxdh_user_bundle(
    user_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed key bundle info for a specific user."""
    bundle_result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id).limit(1)
    )
    bundle = bundle_result.scalar_one_or_none()
    
    if not bundle:
        return {
            "has_bundle": False,
            "has_pq_key": False,
            "prekeys_remaining": 0,
            "signed_prekey_id": None,
            "signed_prekey_age_days": 0,
            "needs_replenishment": True,
            "needs_spk_rotation": False,
            "pq_kem_key_length": 0
        }
    
    # Parse prekeys
    try:
        prekeys = json.loads(bundle.one_time_prekeys or "[]")
        prekey_count = len(prekeys)
    except (json.JSONDecodeError, TypeError):
        prekey_count = 0
    
    has_pq = bool(bundle.pq_kem_public_key and bundle.pq_kem_public_key.strip())
    
    # SPK age
    spk_age_days = 0
    if hasattr(bundle, 'signed_prekey_created_at') and bundle.signed_prekey_created_at:
        age = datetime.now(timezone.utc) - bundle.signed_prekey_created_at
        spk_age_days = age.days
    
    return {
        "has_bundle": True,
        "has_pq_key": has_pq,
        "prekeys_remaining": prekey_count,
        "signed_prekey_id": bundle.signed_prekey_id,
        "signed_prekey_age_days": spk_age_days,
        "needs_replenishment": prekey_count < 10,
        "needs_spk_rotation": spk_age_days > 30,
        "pq_kem_key_length": len(bundle.pq_kem_public_key) if has_pq else 0
    }


@router.post("/e2ee/pqxdh/force-rotation/{user_id}")
async def force_pqxdh_rotation(
    user_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Force key rotation for a user by deleting their key bundle.
    
    On next login, the client (vibe-crypto.js v2.0+) will automatically
    generate a new PQXDH key bundle with ML-KEM-768 + X25519.
    """
    # Find user
    user_result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete key bundle
    bundle_result = await db.execute(
        select(KeyBundle).where(KeyBundle.user_id == user_id)
    )
    bundle = bundle_result.scalar_one_or_none()
    
    had_pq = False
    if bundle:
        had_pq = bool(bundle.pq_kem_public_key and bundle.pq_kem_public_key.strip())
        await db.delete(bundle)
    
    # Audit log
    audit = AuditLog(
        event_type=AuditEventType.ADMIN_ACTION,
        severity=AuditSeverity.WARNING,
        user_id=admin.id,
        target_user_id=user_id,
        details=json.dumps({
            "action": "pqxdh_force_rotation",
            "target_username": user.username,
            "had_pq_key": had_pq,
            "admin": admin.username
        }),
        ip_address="admin-panel"
    )
    db.add(audit)
    
    await db.commit()
    
    return {
        "success": True,
        "user_id": user_id,
        "username": user.username,
        "had_pq_key": had_pq,
        "message": f"Key bundle deleted for {user.username}. New PQXDH bundle will be generated on next login."
    }


# ==================== MESSAGES MANAGEMENT ====================

class AdminMessageSend(BaseModel):
    """Schema for admin sending a message to a user."""
    recipient_id: str = Field(..., description="User ID to send message to")
    text: str = Field(..., min_length=1, max_length=10000, description="Message text")


@router.post("/messages/send")
async def admin_send_message(
    message: AdminMessageSend,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Send a plaintext message to a user from admin.
    
    v3.1: This sends an unencrypted system message that will:
    - Display with 🔓 indicator in the client
    - Show as from "VibeAdmin" in a separate system chat
    """
    import base64
    import uuid
    from app.models.message import Message, MessageStatus, MessageType
    
    # Verify recipient exists
    result = await db.execute(select(User).where(User.id == message.recipient_id))
    recipient = result.scalar_one_or_none()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Encode message as base64 (legacy/unencrypted format)
    encoded_payload = base64.b64encode(message.text.encode('utf-8')).decode('utf-8')
    
    # Use special system sender ID for admin messages
    SYSTEM_SENDER_ID = "00000000-0000-0000-0000-000000000000"
    
    # Create message
    db_message = Message(
        id=str(uuid.uuid4()),
        sender_id=SYSTEM_SENDER_ID,  # System sender, not admin's personal account
        recipient_id=message.recipient_id,
        message_type=MessageType.TEXT,
        encrypted_payload=encoded_payload,
        status=MessageStatus.SENT,
    )
    
    db.add(db_message)
    await db.commit()
    await db.refresh(db_message)
    
    # Send via WebSocket if recipient is online
    ws_payload = {
        "id": db_message.id,
        "sender_id": SYSTEM_SENDER_ID,
        "sender_name": "VibeAdmin",
        "recipient_id": message.recipient_id,
        "message_type": "text",
        "encrypted_payload": encoded_payload,
        "created_at": db_message.created_at.isoformat(),
        "status": "sent",
        "is_admin_message": True,  # Flag for client to handle specially
        "is_e2ee": False,  # Explicitly mark as not encrypted
    }
    
    from app.models.message import WSMessage, WSMessageType
    ws_message = WSMessage(type=WSMessageType.NEW_MESSAGE, payload=ws_payload)
    delivered = await ws_manager.send_to_user(message.recipient_id, ws_message)
    
    if delivered:
        db_message.status = MessageStatus.DELIVERED
        await db.commit()
    
    return {
        "status": "ok",
        "message_id": db_message.id,
        "delivered": delivered,
        "recipient": recipient.display_name or recipient.username
    }


@router.get("/messages")
async def search_messages(
    sender_id: Optional[str] = Query(None, description="Filter by sender"),
    recipient_id: Optional[str] = Query(None, description="Filter by recipient"),
    group_id: Optional[str] = Query(None, description="Filter by group"),
    message_type: Optional[str] = Query(None, description="Filter by type: text, file, voice, poll"),
    date_from: Optional[datetime] = Query(None, description="Start date"),
    date_to: Optional[datetime] = Query(None, description="End date"),
    include_deleted: bool = Query(False, description="Include deleted messages"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Search messages by metadata (not content - E2EE encrypted)."""
    
    # Build query conditions
    conditions = []
    
    # Filter deleted messages unless include_deleted is True
    if not include_deleted:
        # Show messages that are visible to at least one participant
        conditions.append(
            or_(
                Message.deleted_for_sender == False,
                Message.deleted_for_recipient == False
            )
        )
    
    if sender_id:
        conditions.append(Message.sender_id == sender_id)
    
    if recipient_id:
        conditions.append(Message.recipient_id == recipient_id)
    
    if group_id:
        conditions.append(Message.group_id == group_id)
    
    if message_type:
        conditions.append(Message.message_type == message_type)
    
    if date_from:
        conditions.append(Message.created_at >= date_from)
    
    if date_to:
        conditions.append(Message.created_at <= date_to)
    
    # Build statement
    stmt = select(Message)
    if conditions:
        stmt = stmt.where(and_(*conditions))
    
    # Get total count
    count_stmt = select(func.count(Message.id))
    if conditions:
        count_stmt = count_stmt.where(and_(*conditions))
    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0
    
    # Apply pagination
    stmt = stmt.order_by(desc(Message.created_at))
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(stmt)
    messages = result.scalars().all()
    
    # Enrich with user info
    user_cache = {}
    message_list = []
    
    async def get_user_name(user_id: str) -> str:
        """Get user display name with caching."""
        if not user_id:
            return None
        if user_id not in user_cache:
            user_result = await db.execute(select(User).where(User.id == user_id))
            user_cache[user_id] = user_result.scalar_one_or_none()
        user = user_cache.get(user_id)
        return user.display_name if user else "Unknown"
    
    for msg in messages:
        sender_name = await get_user_name(msg.sender_id)
        recipient_id = getattr(msg, 'recipient_id', None)
        recipient_name = await get_user_name(recipient_id) if recipient_id else None
        
        message_list.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": sender_name,
            "recipient_id": recipient_id,
            "recipient_name": recipient_name,
            "group_id": getattr(msg, 'group_id', None),
            "message_type": getattr(msg, 'message_type', 'text'),
            "created_at": msg.created_at.isoformat() if msg.created_at else None,
            "is_encrypted": True,  # E2EE - content not readable
            "has_attachment": getattr(msg, 'file_id', None) is not None,
            "deleted_for_sender": getattr(msg, 'deleted_for_sender', False),
            "deleted_for_recipient": getattr(msg, 'deleted_for_recipient', False)
        })
    
    return {
        "messages": message_list,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (page * page_size) < total
    }


@router.get("/messages/stats")
async def get_message_stats(
    days: int = Query(7, ge=1, le=90),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get message statistics by type."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Filter for non-deleted messages (visible to at least one participant)
    not_deleted = or_(
        Message.deleted_for_sender == False,
        Message.deleted_for_recipient == False
    )
    
    # Total messages (non-deleted)
    total_result = await db.execute(
        select(func.count(Message.id)).where(not_deleted)
    )
    total = total_result.scalar() or 0
    
    # Messages in period (non-deleted)
    period_result = await db.execute(
        select(func.count(Message.id))
        .where(and_(Message.created_at >= start_date, not_deleted))
    )
    period_total = period_result.scalar() or 0
    
    # By type (if message_type field exists)
    by_type = {}
    try:
        type_result = await db.execute(
            select(Message.message_type, func.count(Message.id))
            .where(and_(Message.created_at >= start_date, not_deleted))
            .group_by(Message.message_type)
        )
        by_type = {row[0] or "text": row[1] for row in type_result.all()}
    except Exception:
        # Fallback if message_type doesn't exist
        by_type = {"text": period_total}
    
    # Messages per day
    daily_result = await db.execute(
        select(
            func.date(Message.created_at).label('date'),
            func.count(Message.id).label('count')
        )
        .where(Message.created_at >= start_date)
        .group_by(func.date(Message.created_at))
        .order_by(func.date(Message.created_at))
    )
    daily = [{"date": str(row[0]), "count": row[1]} for row in daily_result.all()]
    
    # Top senders
    top_senders_result = await db.execute(
        select(Message.sender_id, func.count(Message.id).label('count'))
        .where(Message.created_at >= start_date)
        .group_by(Message.sender_id)
        .order_by(desc('count'))
        .limit(10)
    )
    
    top_senders = []
    for row in top_senders_result.all():
        user_result = await db.execute(select(User).where(User.id == row[0]))
        user = user_result.scalar_one_or_none()
        top_senders.append({
            "user_id": row[0],
            "username": user.username if user else "Unknown",
            "display_name": user.display_name if user else "Unknown",
            "message_count": row[1]
        })
    
    return {
        "period_days": days,
        "total_all_time": total,
        "total_in_period": period_total,
        "by_type": by_type,
        "daily": daily,
        "top_senders": top_senders
    }


@router.delete("/messages/by-user/{user_id}")
async def delete_user_messages(
    user_id: str,
    days: int = Query(7, ge=1, le=30, description="Delete messages from last N days"),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete all messages from a specific user (spam cleanup)."""
    # Verify user exists
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Count messages to delete
    count_result = await db.execute(
        select(func.count(Message.id))
        .where(
            Message.sender_id == user_id,
            Message.created_at >= start_date
        )
    )
    count = count_result.scalar() or 0
    
    if count == 0:
        return {"status": "ok", "message": "No messages found to delete", "deleted_count": 0}
    
    # КАО#379: purge through the shared helper instead of a raw Core delete. Only three tables have a
    # real FK to messages (reactions / saved / per-user deletions, all ON DELETE CASCADE); pinned_messages,
    # favorite_messages, polls.message_id and messages.reply_to_id have NO foreign key and were left
    # dangling by the old statement - and a dangling pin is user-visible AND unrepairable through the API,
    # because the limit check counts pin rows without joining messages while unpin loads the Message first
    # and 404s. file_metadata.message_id is ON DELETE SET NULL while the GC only reclaims is_attached=false,
    # so the old delete also stranded the encrypted blobs for ever.
    from app.services.message_purge import purge_messages

    doomed = (await db.execute(
        select(Message.id).where(
            Message.sender_id == user_id,
            Message.created_at >= start_date
        )
    )).scalars().all()
    purge = await purge_messages(db, list(doomed))
    await db.commit()
    
    # Log action
    await log_audit_event(
        db,
        "admin_delete_messages",
        "warning",
        admin.id,
        f"Deleted {count} messages from user {user.username}",
        target_user_id=user_id
    )
    
    return {
        "status": "ok",
        "message": f"Deleted {count} messages from {user.username}",
        "deleted_count": count
    }


class BatchMessagesRequest(BaseModel):
    """Request model for batch message deletion."""
    message_ids: List[str] = Field(..., max_length=1000)


@router.delete("/messages/batch")
async def admin_batch_delete_messages(
    request: BatchMessagesRequest = Body(...),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete multiple messages by ID (admin only)."""
    if not request.message_ids:
        raise HTTPException(status_code=400, detail="No message IDs provided")
    
    if len(request.message_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 messages per request")
    
    # Count existing messages
    count_result = await db.execute(
        select(func.count(Message.id)).where(Message.id.in_(request.message_ids))
    )
    count = count_result.scalar() or 0
    
    if count == 0:
        return {"status": "ok", "deleted_count": 0, "message": "No messages found"}
    
    # КАО#379: same shared purge - see the comment on /messages/by-user.
    from app.services.message_purge import purge_messages

    doomed = (await db.execute(
        select(Message.id).where(Message.id.in_(request.message_ids))
    )).scalars().all()
    purge = await purge_messages(db, list(doomed))
    await db.commit()
    
    # Log action
    await log_audit_event(
        db,
        "admin_batch_delete_messages",
        "warning",
        admin.id,
        f"Batch deleted {count} messages"
    )
    
    return {
        "status": "ok",
        "deleted_count": count,
        "message": f"Deleted {count} messages"
    }


# ==================== BACKUP MANAGEMENT ====================

BACKUP_DIR = os.environ.get("BACKUP_DIR", "/mnt/backup")
PROJECT_DIR = "/app"


@router.get("/backups")
async def list_backups(
    admin: User = Depends(require_admin),
):
    """Get list of available backups."""
    if not os.path.exists(BACKUP_DIR):
        return {"backups": [], "backup_dir": BACKUP_DIR, "error": "Backup directory not found"}
    
    # Find all backup files
    pattern = os.path.join(BACKUP_DIR, "vibemessenger-backup-*.tar.gz")
    backup_files = glob.glob(pattern)
    
    backups = []
    for filepath in sorted(backup_files, reverse=True):
        filename = os.path.basename(filepath)
        try:
            stat = os.stat(filepath)
            timestamp_str = filename.replace("vibemessenger-backup-", "").replace(".tar.gz", "")
            
            backups.append({
                "filename": filename,
                "size": stat.st_size,
                "size_human": format_size(stat.st_size),
                "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "timestamp": timestamp_str,
            })
        except Exception:
            continue
    
    # Get disk space info
    try:
        stat_vfs = os.statvfs(BACKUP_DIR)
        disk_free = stat_vfs.f_bavail * stat_vfs.f_frsize
        disk_total = stat_vfs.f_blocks * stat_vfs.f_frsize
    except Exception:
        disk_free = 0
        disk_total = 0
    
    return {
        "backups": backups,
        "backup_dir": BACKUP_DIR,
        "disk_free": format_size(disk_free),
        "disk_total": format_size(disk_total),
    }


@router.post("/backups")
async def create_backup(
    admin: User = Depends(require_admin),
):
    """Create a new backup."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    backup_name = f"vibemessenger-backup-{timestamp}"
    temp_dir = f"/tmp/{backup_name}"
    archive_path = os.path.join(BACKUP_DIR, f"{backup_name}.tar.gz")
    
    try:
        os.makedirs(temp_dir, exist_ok=True)
        
        # Database backup
        db_file = os.path.join(temp_dir, "database.sql")
        try:
            result = subprocess.run(
                ["pg_dump", "-h", "postgres", "-U", "messenger", "messenger"],
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, "PGPASSWORD": os.environ.get("POSTGRES_PASSWORD", "messenger")}
            )
            if result.returncode == 0:
                with open(db_file, "w") as f:
                    f.write(result.stdout)
            else:
                return {"status": "error", "message": f"Database backup failed: {result.stderr}"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Database backup timed out"}
        except Exception as e:
            return {"status": "error", "message": f"Database backup failed: {str(e)}"}
        
        # Copy data directories
        data_dirs = ["avatars", "group_avatars", "uploads"]
        stats = {}
        
        for dir_name in data_dirs:
            src_dir = f"/app/data/{dir_name}"
            dst_dir = os.path.join(temp_dir, dir_name)
            
            if os.path.exists(src_dir):
                shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
                file_count = sum(1 for _ in glob.glob(os.path.join(dst_dir, "*")))
                stats[dir_name] = file_count
            else:
                os.makedirs(dst_dir, exist_ok=True)
                stats[dir_name] = 0
        
        # Create metadata
        metadata = {
            "backup_version": "2.0",
            "app_version": APP_VERSION,
            "created_at": datetime.now().isoformat(),
            "created_by": admin.username,
            "stats": stats,
        }
        with open(os.path.join(temp_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Create archive
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(temp_dir, arcname=backup_name)
        
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        archive_size = os.path.getsize(archive_path)
        
        return {
            "status": "ok",
            "message": "Backup created successfully",
            "filename": f"{backup_name}.tar.gz",
            "size": format_size(archive_size),
            "stats": stats,
        }
        
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if os.path.exists(archive_path):
            os.remove(archive_path)
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")


@router.delete("/backups/{filename}")
async def delete_backup(
    filename: str,
    admin: User = Depends(require_admin),
):
    """Delete a backup file."""
    if not filename.startswith("vibemessenger-backup-") or not filename.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Invalid backup filename")
    
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    filepath = os.path.join(BACKUP_DIR, filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Backup not found")
    
    try:
        os.remove(filepath)
        return {"status": "ok", "message": f"Backup {filename} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete backup: {str(e)}")


# ==================== STATISTICS ====================

@router.get("/stats")
async def get_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get extended server statistics for dashboard."""
    from app.models.group import Group
    from app.models.poll import Poll
    from app.models.file import FileMetadata
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    
    # Users stats
    total_users = await db.execute(select(func.count(User.id)))
    total_users = total_users.scalar() or 0
    
    blocked_users = await db.execute(
        select(func.count(User.id)).where(User.is_blocked == True)
    )
    blocked_users = blocked_users.scalar() or 0
    
    # Online users and WebSocket connections
    try:
        ws_connections = sum(len(conns) for conns in ws_manager._connections.values())
        online_users = len(ws_manager._connections)
    except Exception:
        ws_connections = 0
        online_users = 0
    
    # Groups stats
    total_groups = await db.execute(
        select(func.count(Group.id)).where(Group.is_deleted == False)
    )
    total_groups = total_groups.scalar() or 0
    
    # Messages stats - exclude deleted messages
    msg_not_deleted = or_(
        Message.deleted_for_sender == False,
        Message.deleted_for_recipient == False
    )
    
    messages_today = await db.execute(
        select(func.count(Message.id)).where(
            and_(Message.created_at >= today_start, msg_not_deleted)
        )
    )
    messages_today = messages_today.scalar() or 0
    
    messages_week = await db.execute(
        select(func.count(Message.id)).where(
            and_(Message.created_at >= week_start, msg_not_deleted)
        )
    )
    messages_week = messages_week.scalar() or 0
    
    total_messages = await db.execute(
        select(func.count(Message.id)).where(msg_not_deleted)
    )
    total_messages = total_messages.scalar() or 0
    
    # Polls stats
    active_polls = await db.execute(
        select(func.count(Poll.id)).where(Poll.is_closed == False)
    )
    active_polls = active_polls.scalar() or 0
    
    total_polls = await db.execute(select(func.count(Poll.id)))
    total_polls = total_polls.scalar() or 0
    
    # Files stats
    total_files = await db.execute(select(func.count(FileMetadata.id)))
    total_files = total_files.scalar() or 0
    
    files_size = await db.execute(select(func.sum(FileMetadata.size_bytes)))
    files_size = files_size.scalar() or 0
    
    # Database size
    db_size = 0
    try:
        db_size_result = await db.execute(
            select(func.pg_database_size(func.current_database()))
        )
        db_size = db_size_result.scalar() or 0
    except Exception:
        db_path = os.environ.get("DATABASE_PATH", "/data/messenger.db")
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
    
    # Last backup
    last_backup = None
    backup_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "vibemessenger-backup-*.tar.gz")), reverse=True)
    if backup_files:
        last_backup = os.path.basename(backup_files[0])
    
    # Server uptime
    uptime_seconds = int(time.time() - SERVER_START_TIME)
    uptime_str = format_uptime(uptime_seconds)
    
    # System resources
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used = format_size(memory.used)
        memory_total = format_size(memory.total)
    except Exception:
        cpu_percent = 0
        memory_percent = 0
        memory_used = "N/A"
        memory_total = "N/A"
    
    # Recent errors (from audit log)
    recent_errors = await db.execute(
        select(AuditLog)
        .where(AuditLog.severity.in_(["error", "critical"]))
        .order_by(desc(AuditLog.created_at))
        .limit(5)
    )
    errors = []
    for log in recent_errors.scalars().all():
        errors.append({
            "event": log.event_type,
            "severity": log.severity,
            "time": log.created_at.isoformat() if log.created_at else None,
            "details": log.details[:100] if log.details else None
        })
    
    # v3.2: WebAuthn / Passkeys stats
    users_with_passkeys = 0
    total_passkeys = 0
    try:
        pk_users = await db.execute(
            select(func.count(distinct(WebAuthnCredential.user_id)))
        )
        users_with_passkeys = pk_users.scalar() or 0
        
        pk_total = await db.execute(select(func.count(WebAuthnCredential.id)))
        total_passkeys = pk_total.scalar() or 0
    except Exception:
        pass
    
    # v3.3: PQXDH stats
    pq_bundles = 0
    total_key_bundles = 0
    users_with_keys = 0
    try:
        pq_result = await db.execute(
            select(func.count(KeyBundle.id)).where(
                and_(
                    KeyBundle.pq_kem_public_key.isnot(None),
                    KeyBundle.pq_kem_public_key != ""
                )
            )
        )
        pq_bundles = pq_result.scalar() or 0
        
        total_kb = await db.execute(select(func.count(KeyBundle.id)))
        total_key_bundles = total_kb.scalar() or 0
        
        uwk = await db.execute(select(func.count(distinct(KeyBundle.user_id))))
        users_with_keys = uwk.scalar() or 0
    except Exception:
        pass
    
    return {
        "users": {
            "total": total_users,
            "online": online_users,
            "blocked": blocked_users
        },
        "groups": {
            "total": total_groups
        },
        "messages": {
            "total": total_messages,
            "today": messages_today,
            "week": messages_week
        },
        "sessions": {
            "active": ws_connections
        },
        "websocket": {
            "connections": ws_connections,
            "unique_users": online_users
        },
        "polls": {
            "total": total_polls,
            "active": active_polls
        },
        "storage": {
            "database_size": format_size(db_size),
            "files_count": total_files,
            "files_size": format_size(files_size)
        },
        "backup": {
            "last": last_backup
        },
        "server": {
            "version": APP_VERSION,
            "uptime": uptime_str,
            "uptime_seconds": uptime_seconds,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "memory_used": memory_used,
            "memory_total": memory_total
        },
        "recent_errors": errors,
        "webauthn": {
            "users_with_passkeys": users_with_passkeys,
            "total_passkeys": total_passkeys
        },
        "e2ee": {
            "users_with_keys": users_with_keys
        },
        "pqxdh": {
            "pq_bundles": pq_bundles,
            "total_bundles": total_key_bundles,
            "classic_bundles": total_key_bundles - pq_bundles
        },
        "server_time": now.isoformat()
    }


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": APP_VERSION,
        "uptime": format_uptime(int(time.time() - SERVER_START_TIME)),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/version")
async def get_version():
    """Get server version info."""
    return {
        "version": APP_VERSION,
        "api_version": "2.0",
        "uptime": format_uptime(int(time.time() - SERVER_START_TIME))
    }


# ==================== POLLS MANAGEMENT ====================

@router.get("/polls")
async def get_all_polls(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all polls for admin management."""
    from sqlalchemy.orm import selectinload
    from app.models.poll import Poll, PollVote
    
    result = await db.execute(
        select(Poll).options(selectinload(Poll.votes)).order_by(Poll.created_at.desc())
    )
    polls = result.scalars().all()
    
    poll_list = []
    for poll in polls:
        creator = await db.execute(select(User).where(User.id == poll.creator_id))
        creator = creator.scalar_one_or_none()
        creator_name = creator.display_name if creator else "Unknown"
        
        voter_ids = set()
        for vote in poll.votes:
            voter_ids.add(vote.user_id)
        
        status = "active"
        if poll.is_closed:
            status = "closed"
        elif poll.expires_at and datetime.utcnow() > poll.expires_at:
            status = "expired"
        
        # КАО#231 (SER#18): poll questions are E2EE ("e2e:" prefix) — the admin cannot decrypt them
        # (zero-knowledge by design). Surface a clean placeholder instead of raw ciphertext.
        admin_question = "🔒 (end-to-end encrypted)" if isinstance(poll.question, str) and poll.question.startswith("e2e:") else poll.question
        poll_list.append({
            "id": poll.id,
            "question": admin_question,
            "options_count": len(poll.options),
            "creator_id": poll.creator_id,
            "creator_name": creator_name,
            "votes_count": len(voter_ids),
            "status": status,
            "is_anonymous": poll.is_anonymous,
            "is_multiple": poll.is_multiple,
            "created_at": poll.created_at.isoformat() if poll.created_at else None,
            "expires_at": poll.expires_at.isoformat() if poll.expires_at else None,
            "chat_id": poll.chat_id,
            "group_id": poll.group_id
        })
    
    return {"polls": poll_list, "total": len(poll_list)}


@router.post("/polls/{poll_id}/close")
async def admin_close_poll(
    poll_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Close a poll (admin action)."""
    from app.models.poll import Poll
    
    result = await db.execute(select(Poll).where(Poll.id == poll_id))
    poll = result.scalar_one_or_none()
    
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if poll.is_closed:
        raise HTTPException(status_code=400, detail="Poll is already closed")
    
    poll.is_closed = True
    await db.commit()
    
    return {"status": "ok", "message": "Poll closed"}


@router.delete("/polls/{poll_id}")
async def admin_delete_poll(
    poll_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete a poll (admin action)."""
    from app.models.poll import Poll
    
    result = await db.execute(select(Poll).where(Poll.id == poll_id))
    poll = result.scalar_one_or_none()
    
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    await db.delete(poll)
    await db.commit()
    
    return {"status": "ok", "message": "Poll deleted"}


class BatchPollsRequest(BaseModel):
    """Request model for batch poll operations."""
    poll_ids: List[str]


@router.post("/polls/batch/close")
async def admin_batch_close_polls(
    request: BatchPollsRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Close multiple polls in one request."""
    from app.models.poll import Poll
    
    if not request.poll_ids:
        raise HTTPException(status_code=400, detail="No poll IDs provided")
    
    if len(request.poll_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 polls per batch")
    
    # Update all polls in one query
    result = await db.execute(
        select(Poll).where(Poll.id.in_(request.poll_ids))
    )
    polls = result.scalars().all()
    
    closed_count = 0
    already_closed = 0
    not_found = len(request.poll_ids) - len(polls)
    
    for poll in polls:
        if poll.is_closed:
            already_closed += 1
        else:
            poll.is_closed = True
            closed_count += 1
    
    await db.commit()
    
    return {
        "status": "ok",
        "closed": closed_count,
        "already_closed": already_closed,
        "not_found": not_found,
        "total_requested": len(request.poll_ids)
    }


@router.delete("/polls/batch")
async def admin_batch_delete_polls(
    request: BatchPollsRequest = Body(...),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete multiple polls in one request."""
    from app.models.poll import Poll
    
    if not request.poll_ids:
        raise HTTPException(status_code=400, detail="No poll IDs provided")
    
    if len(request.poll_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 polls per batch")
    
    # Delete all polls in one query
    result = await db.execute(
        select(Poll).where(Poll.id.in_(request.poll_ids))
    )
    polls = result.scalars().all()
    
    deleted_count = 0
    not_found = len(request.poll_ids) - len(polls)
    
    for poll in polls:
        await db.delete(poll)
        deleted_count += 1
    
    await db.commit()
    
    return {
        "status": "ok",
        "deleted": deleted_count,
        "not_found": not_found,
        "total_requested": len(request.poll_ids)
    }


# ==================== AUDIT LOGS ====================

class AuditLogInfo(BaseModel):
    id: str
    event_type: str
    severity: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    target_user_id: Optional[str] = None
    target_resource_id: Optional[str] = None
    target_resource_type: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogsResponse(BaseModel):
    logs: List[AuditLogInfo]
    total: int
    page: int
    page_size: int
    has_more: bool


@router.get("/audit-logs", response_model=AuditLogsResponse)
async def get_audit_logs(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    days: int = Query(7, ge=1, le=90, description="Number of days to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=10, le=200, description="Items per page"),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get audit logs with optional filtering."""
    stmt = select(AuditLog)
    conditions = []
    
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    conditions.append(AuditLog.created_at >= start_date)
    
    if event_type:
        conditions.append(AuditLog.event_type == event_type)
    
    if severity:
        conditions.append(AuditLog.severity == severity)
    
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    
    if ip_address:
        conditions.append(AuditLog.ip_address == ip_address)
    
    if conditions:
        stmt = stmt.where(and_(*conditions))
    
    count_stmt = select(func.count(AuditLog.id)).where(and_(*conditions)) if conditions else select(func.count(AuditLog.id))
    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0
    
    stmt = stmt.order_by(desc(AuditLog.created_at))
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(stmt)
    logs = result.scalars().all()
    
    return AuditLogsResponse(
        logs=[AuditLogInfo.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total
    )


@router.get("/audit-logs/event-types")
async def get_audit_event_types(
    admin: User = Depends(require_admin),
):
    """Get list of all audit event types."""
    return {
        "event_types": [e.value for e in AuditEventType],
        "severities": [s.value for s in AuditSeverity]
    }


@router.get("/audit-logs/stats")
async def get_audit_stats(
    days: int = Query(7, ge=1, le=90),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get audit log statistics."""
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    total_result = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.created_at >= start_date)
    )
    total = total_result.scalar() or 0
    
    type_result = await db.execute(
        select(AuditLog.event_type, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start_date)
        .group_by(AuditLog.event_type)
    )
    by_type = {row[0]: row[1] for row in type_result.all()}
    
    severity_result = await db.execute(
        select(AuditLog.severity, func.count(AuditLog.id))
        .where(AuditLog.created_at >= start_date)
        .group_by(AuditLog.severity)
    )
    by_severity = {row[0]: row[1] for row in severity_result.all()}
    
    failed_logins = by_type.get("login_failed", 0)
    
    ip_result = await db.execute(
        select(func.count(distinct(AuditLog.ip_address)))
        .where(AuditLog.created_at >= start_date)
    )
    unique_ips = ip_result.scalar() or 0
    
    return {
        "total": total,
        "by_event_type": by_type,
        "by_severity": by_severity,
        "failed_logins": failed_logins,
        "unique_ips": unique_ips,
        "days": days
    }


# ==================== HELPER FUNCTIONS ====================

def format_size(size_bytes: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def format_uptime(seconds: int) -> str:
    """Format uptime to human readable string."""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"


async def log_audit_event(
    db: AsyncSession,
    event_type: str,
    severity: str,
    user_id: str,
    details: str,
    target_user_id: str = None,
    ip_address: str = None
):
    """Helper function to log audit events."""
    try:
        log = AuditLog(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            details=details,
            target_user_id=target_user_id,
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc)
        )
        db.add(log)
        await db.commit()
    except Exception:
        pass  # Don't fail main operation if logging fails
