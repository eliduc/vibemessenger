"""
Database models.
"""
# Import all models so SQLAlchemy can discover them
from app.models.user import User, KeyBundle, PushSubscription, WebAuthnCredential
from app.models.message import Message
from app.models.group import Group, GroupMember, GroupInvite
from app.models.file import FileMetadata
from app.models.poll import Poll, PollVote, FavoriteMessage
from app.models.audit import AuditLog

__all__ = [
    "User",
    "KeyBundle", 
    "PushSubscription",
    "WebAuthnCredential",
    "Message",
    "Group",
    "GroupMember",
    "GroupInvite",
    "FileMetadata",
    "Poll",
    "PollVote",
    "FavoriteMessage",
    "AuditLog",
]
