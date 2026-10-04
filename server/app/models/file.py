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
File metadata model for persistent file tracking.
"""
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Column, String, Boolean, DateTime, BigInteger, ForeignKey, Index
from sqlalchemy.orm import relationship
from pydantic import BaseModel

from app.database import Base, TimestampMixin


class FileMetadata(Base, TimestampMixin):
    """
    Persistent file metadata storage.
    
    Replaces in-memory file_owners dict to survive restarts
    and enable quotas, garbage collection, etc.
    """
    __tablename__ = "file_metadata"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Owner
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # File info
    file_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID used in filename
    original_filename = Column(String(256), nullable=True)  # Original uploaded filename
    extension = Column(String(10), nullable=True)  # File extension
    mime_type = Column(String(100), nullable=True)
    size_bytes = Column(BigInteger, nullable=False, default=0)
    
    # Lifecycle
    is_attached = Column(Boolean, default=False)  # True if referenced by a message
    message_id = Column(String(36), ForeignKey("messages.id", ondelete="SET NULL"), nullable=True)
    
    # Timestamps
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    attached_at = Column(DateTime(timezone=True), nullable=True)
    
    # Indexes for garbage collection queries
    __table_args__ = (
        Index('ix_file_metadata_unattached', 'is_attached', 'uploaded_at'),
        Index('ix_file_metadata_user_size', 'user_id', 'size_bytes'),
    )


# ============== Pydantic Schemas ==============

class FileMetadataResponse(BaseModel):
    """Response schema for file metadata."""
    file_id: str
    original_filename: str | None
    extension: str | None
    size_bytes: int
    is_attached: bool
    uploaded_at: datetime
    
    class Config:
        from_attributes = True


class UserStorageStats(BaseModel):
    """User storage statistics."""
    used_bytes: int
    quota_bytes: int
    file_count: int
    used_percent: float
