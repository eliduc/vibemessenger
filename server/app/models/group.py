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
Group chat models and schemas.
"""
from datetime import datetime
from enum import Enum
from uuid import uuid4
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Enum as SQLEnum, UniqueConstraint
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field

from app.database import Base


class GroupRole(str, Enum):
    """Role within a group."""
    OWNER = "owner"
    ADMIN = "admin"
    MODERATOR = "moderator"
    MEMBER = "member"
    SUBSCRIBER = "subscriber"


# Permission levels for role hierarchy
ROLE_HIERARCHY = {
    "owner": 4,
    "admin": 3,
    "moderator": 2,
    "member": 1,
    "subscriber": 0,
}


def can_manage_role(actor_role: str, target_role: str) -> bool:
    """Check if actor can manage target's role."""
    return ROLE_HIERARCHY.get(actor_role, 0) > ROLE_HIERARCHY.get(target_role, 0)


class Group(Base):
    """Group chat."""
    __tablename__ = "groups"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    avatar_url = Column(String(256), nullable=True)
    
    created_by = Column(String(36), nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    is_deleted = Column(Boolean, default=False)
    
    # Public group / Invite link settings (v3.9.0)
    is_public = Column(Boolean, default=False)  # If true, group can be found in search
    invite_code = Column(String(16), nullable=True, unique=True, index=True)  # Unique invite code
    invite_link_enabled = Column(Boolean, default=False)  # If invite link is active
    
    # Channel mode (v3.11.10)
    is_channel = Column(Boolean, default=False)  # If true, only owner/admin can post
    
    # Relationships
    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")


class GroupMember(Base):
    """Group membership."""
    __tablename__ = "group_members"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    group_id = Column(String(36), ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), nullable=False, index=True)
    
    role = Column(String(20), default="member")
    joined_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # For notifications
    is_muted = Column(Boolean, default=False)
    last_read_at = Column(DateTime(timezone=True), nullable=True)

    # КАО#250 (#15): one membership row per (group, user) — blocks duplicate rows from concurrent
    # add_members / join-by-invite / respond_to_invite races. Migration dedups then ADDs this constraint.
    __table_args__ = (
        UniqueConstraint('group_id', 'user_id', name='uq_group_members_group_user'),
    )

    # Relationships
    group = relationship("Group", back_populates="members")


class InviteStatus(str, Enum):
    """Invite status."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"


class GroupInvite(Base):
    """Group invitation."""
    __tablename__ = "group_invites"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    group_id = Column(String(36), ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    inviter_id = Column(String(36), nullable=False)  # Who sent the invite
    invitee_id = Column(String(36), nullable=False, index=True)  # Who is invited
    
    status = Column(String(20), default="pending")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    responded_at = Column(DateTime(timezone=True), nullable=True)


# ============== Pydantic Schemas ==============

class GroupCreate(BaseModel):
    """Schema for creating a group."""
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    member_ids: list[str] = Field(default_factory=list, description="Initial member user IDs")
    is_channel: bool = False  # v3.11.10: Create as channel


class GroupUpdate(BaseModel):
    """Schema for updating a group."""
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)


class GroupMemberInfo(BaseModel):
    """Schema for group member info."""
    user_id: str
    username: str
    display_name: str
    avatar_url: str | None = None
    role: GroupRole
    joined_at: datetime
    
    class Config:
        from_attributes = True


class GroupResponse(BaseModel):
    """Schema for group response."""
    id: str
    name: str
    description: str | None
    avatar_url: str | None = None
    created_by: str
    created_at: datetime
    member_count: int = 0
    members: list[GroupMemberInfo] = []
    # Invite link fields (v3.9.0)
    is_public: bool = False
    invite_link_enabled: bool = False
    invite_code: str | None = None
    # Channel fields (v3.11.10)
    is_channel: bool = False
    subscriber_count: int = 0
    
    class Config:
        from_attributes = True


class GroupListItem(BaseModel):
    """Schema for group list item."""
    id: str
    name: str
    description: str | None
    member_count: int
    last_message: str | None = None
    last_message_at: datetime | None = None
    unread_count: int = 0
    is_channel: bool = False  # v3.11.10
    
    class Config:
        from_attributes = True


class AddMembersRequest(BaseModel):
    """Schema for adding members."""
    user_ids: list[str] = Field(..., min_items=1)


class RemoveMemberRequest(BaseModel):
    """Schema for removing a member."""
    user_id: str


class GroupInviteResponse(BaseModel):
    """Schema for group invite response."""
    id: str
    group_id: str
    group_name: str
    inviter_id: str
    inviter_name: str
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class InviteAction(BaseModel):
    """Schema for responding to invite."""
    action: str = Field(..., pattern="^(accept|decline)$")


# ============== New Schemas for v3.9.0 ==============

class InviteLinkResponse(BaseModel):
    """Schema for invite link response."""
    invite_code: str
    invite_link: str
    enabled: bool


class GroupPublicInfo(BaseModel):
    """Schema for public group info (for invite link preview)."""
    id: str
    name: str
    description: str | None
    avatar_url: str | None = None
    member_count: int
    is_already_member: bool = False
    is_channel: bool = False  # v3.11.10
    
    class Config:
        from_attributes = True


class ChangeRoleRequest(BaseModel):
    """Schema for changing member role."""
    role: str = Field(..., pattern="^(admin|moderator|member|subscriber)$")


class GroupSettingsUpdate(BaseModel):
    """Schema for updating group settings."""
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    is_public: bool | None = None
