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
