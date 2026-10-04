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
Message model and related schemas.
"""
from datetime import datetime
from uuid import uuid4
from enum import Enum

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Enum as SQLEnum, ForeignKey, UniqueConstraint
from pydantic import BaseModel, Field

from app.database import Base, TimestampMixin


class MessageType(str, Enum):
    """Type of message content."""
    TEXT = "text"
    FILE = "file"
    IMAGE = "image"
    VOICE = "voice"
    KEY_EXCHANGE = "key_exchange"
    RECEIPT = "receipt"
    CALL = "call"  # Call log message (not encrypted)


class MessageStatus(str, Enum):
    """Message delivery status."""
    PENDING = "pending"      # Stored on server, recipient offline
    DELIVERED = "delivered"  # Delivered to recipient device
    READ = "read"           # Read by recipient


# ============== SQLAlchemy Models ==============

class Message(Base, TimestampMixin):
    """
    Encrypted message stored on server.
    
    Server stores only:
    - Metadata (sender, recipient, timestamps)
    - Encrypted payload (opaque blob)
    - Delivery status
    
    Server CANNOT read message content.
    """
    __tablename__ = "messages"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Participants
    sender_id = Column(String(36), nullable=False, index=True)
    recipient_id = Column(String(36), nullable=True, index=True)  # Nullable for group messages
    
    # Group chat support
    group_id = Column(String(36), nullable=True, index=True)  # Set for group messages
    
    # Message type
    message_type = Column(SQLEnum(MessageType), default=MessageType.TEXT)
    
    # Encrypted content (base64)
    # Contains: {ciphertext, nonce, header (DH ratchet info)}
    encrypted_payload = Column(Text, nullable=False)
    
    # For file messages: encrypted metadata
    file_id = Column(String(36), nullable=True)
    
    # Delivery tracking
    status = Column(SQLEnum(MessageStatus), default=MessageStatus.PENDING)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    read_at = Column(DateTime(timezone=True), nullable=True)
    
    # Client-side message ID for deduplication
    client_message_id = Column(String(36), nullable=True, index=True)
    
    # Expiration (optional disappearing messages)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Deletion tracking (soft delete)
    deleted_for_sender = Column(Boolean, default=False)
    deleted_for_recipient = Column(Boolean, default=False)
    
    # Edit tracking
    edited_at = Column(DateTime(timezone=True), nullable=True)
    
    # Forwarding tracking
    forwarded_from_id = Column(String(36), nullable=True)  # Original sender ID
    forwarded_from_name = Column(String(100), nullable=True)  # Original sender display name
    
    # Pinned message
    is_pinned = Column(Boolean, default=False)
    
    # Reply to message
    reply_to_id = Column(String(36), nullable=True, index=True)
    
    # Mentions (JSON array of user_ids, null for @all)
    mentions = Column(Text, nullable=True)  # JSON: ["user_id1", "user_id2"] or ["@all"]


class MessageReaction(Base):
    """
    Reaction to a message.
    One user can have only one reaction per message.
    """
    __tablename__ = "message_reactions"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    message_id = Column(String(36), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    emoji = Column(String(10), nullable=False)  # Emoji character(s)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Ensure one reaction per user per message
    __table_args__ = (
        UniqueConstraint('message_id', 'user_id', name='uq_message_user_reaction'),
    )


class PinnedMessage(Base):
    """
    Pinned messages for chats (direct and groups).
    Max 5 pinned messages per chat.
    """
    __tablename__ = "pinned_messages"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Chat identification (either direct or group)
    # For direct chats: sorted user IDs joined with '_'
    # For groups: group_id
    chat_id = Column(String(100), nullable=False, index=True)
    
    # Message being pinned
    message_id = Column(String(36), nullable=False, index=True)
    
    # Who pinned it
    pinned_by = Column(String(36), nullable=False)
    pinned_at = Column(DateTime(timezone=True), default=datetime.utcnow)


# Note: Poll and PollVote models are defined in app.models.poll

class SavedMessage(Base):
    """
    Bookmarked/saved messages for a user.
    """
    __tablename__ = "saved_messages"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String(36), nullable=False, index=True)
    message_id = Column(String(36), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    saved_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    note = Column(String(500), nullable=True)  # Optional note about why saved
    
    __table_args__ = (
        UniqueConstraint('user_id', 'message_id', name='uq_user_saved_message'),
    )


class FileMetadata(Base, TimestampMixin):
    """
    Metadata for encrypted file uploads.
    
    File content is stored encrypted on disk.
    Only encrypted metadata is stored in DB.
    """
    __tablename__ = "files"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    uploader_id = Column(String(36), nullable=False, index=True)
    
    # Encrypted metadata (filename, mimetype, etc.)
    encrypted_metadata = Column(Text, nullable=False)
    
    # File info
    file_size = Column(Integer, nullable=False)
    chunk_count = Column(Integer, default=1)
    
    # Storage path (relative)
    storage_path = Column(String(256), nullable=False)
    
    # Access control
    is_deleted = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)


# ============== Pydantic Schemas ==============

class MessageSend(BaseModel):
    """Schema for sending a message."""
    recipient_id: str | None = None  # For direct messages
    group_id: str | None = None  # For group messages
    message_type: MessageType = MessageType.TEXT
    encrypted_payload: str = Field(..., description="Base64 encoded encrypted message")
    client_message_id: str | None = None
    file_id: str | None = None
    expires_in_seconds: int | None = Field(None, ge=60, le=604800)  # 1min to 7days
    # Forwarding
    forwarded_from_id: str | None = None
    forwarded_from_name: str | None = None
    # Reply
    reply_to_id: str | None = None
    # Mentions
    mentions: list[str] | None = None  # List of user_ids or ["@all"]
    # E2EE: Sender key distribution for group chats
    sender_key_distribution: dict | None = None


class MessageResponse(BaseModel):
    """Schema for message response."""
    id: str
    sender_id: str
    recipient_id: str | None
    group_id: str | None = None
    message_type: MessageType
    encrypted_payload: str
    file_id: str | None
    status: MessageStatus
    client_message_id: str | None
    created_at: datetime
    delivered_at: datetime | None
    expires_at: datetime | None
    edited_at: datetime | None = None
    forwarded_from_id: str | None = None
    forwarded_from_name: str | None = None
    is_pinned: bool = False
    reply_to_id: str | None = None
    mentions: list[str] | None = None  # List of user_ids or ["@all"]
    # For group messages - sender info
    sender_name: str | None = None
    # E2EE: Sender key distribution for group chats
    sender_key_distribution: dict | None = None
    
    class Config:
        from_attributes = True


class MessageAck(BaseModel):
    """Acknowledge message receipt."""
    message_ids: list[str]
    status: MessageStatus


class MessageEdit(BaseModel):
    """Schema for editing a message."""
    encrypted_payload: str = Field(..., description="New encrypted message content")


class MessagesQuery(BaseModel):
    """Query parameters for fetching messages."""
    after_id: str | None = None
    before_id: str | None = None
    limit: int = Field(default=50, ge=1, le=200)
    contact_id: str | None = None


class FileUploadInit(BaseModel):
    """Initialize chunked file upload."""
    encrypted_metadata: str
    file_size: int = Field(..., gt=0, le=100 * 1024 * 1024)  # Max 100MB
    chunk_size: int = Field(default=1024 * 1024, ge=64 * 1024)  # Default 1MB


class FileUploadResponse(BaseModel):
    """Response after file upload initialization."""
    file_id: str
    upload_urls: list[str]  # URLs for each chunk
    expires_at: datetime


class FileDownloadResponse(BaseModel):
    """Response for file download."""
    file_id: str
    download_url: str
    encrypted_metadata: str
    file_size: int
    expires_at: datetime


# ============== Reaction Schemas ==============

class ReactionRequest(BaseModel):
    """Schema for adding/updating a reaction."""
    emoji: str = Field(..., min_length=1, max_length=10)


class ReactionUserInfo(BaseModel):
    """User info in reaction response."""
    user_id: str
    display_name: str
    
    class Config:
        from_attributes = True


class ReactionInfo(BaseModel):
    """Single reaction with user info."""
    emoji: str
    user_id: str
    display_name: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class ReactionSummary(BaseModel):
    """Summary of reactions for a message."""
    emoji: str
    count: int
    users: list[ReactionUserInfo]


class ReactionsResponse(BaseModel):
    """All reactions for a message."""
    message_id: str
    reactions: list[ReactionSummary]
    user_reaction: str | None = None  # Current user's reaction emoji


# Note: Poll Pydantic schemas (PollCreate, PollVoteRequest, PollOptionResult, PollResponse) 
# are defined in app.models.poll


# ============== Saved Message Schemas ==============

class SaveMessageRequest(BaseModel):
    """Schema for saving a message."""
    note: str | None = Field(None, max_length=500)


class SavedMessageResponse(BaseModel):
    """Saved message with full message data."""
    id: str
    message_id: str
    saved_at: datetime
    note: str | None
    # Message data
    message: MessageResponse
    # Chat info
    chat_name: str | None = None
    chat_id: str | None = None
    is_group: bool = False
    
    class Config:
        from_attributes = True


# ============== Export Schemas ==============

class ExportFormat(str, Enum):
    """Export formats."""
    JSON = "json"
    HTML = "html"
    TXT = "txt"


class ExportRequest(BaseModel):
    """Schema for export request."""
    format: ExportFormat = ExportFormat.JSON
    include_files: bool = False


# ============== WebSocket Message Types ==============

class WSMessageType(str, Enum):
    """WebSocket message types."""
    # Client -> Server
    AUTH = "auth"
    PING = "ping"
    SEND_MESSAGE = "send_message"
    ACK_MESSAGE = "ack_message"
    TYPING = "typing"
    
    # Server -> Client  
    PONG = "pong"
    NEW_MESSAGE = "new_message"
    MESSAGE_SENT = "message_sent"
    MESSAGE_STATUS = "message_status"
    MESSAGE_DELETED = "message_deleted"
    MESSAGE_EDITED = "message_edited"
    POLL_UPDATE = "poll_update"
    MESSAGE_REACTION = "message_reaction"  # New: reaction update
    USER_ONLINE = "user_online"
    USER_OFFLINE = "user_offline"
    USER_TYPING = "user_typing"
    ERROR = "error"
    
    # Calls
    CALL_OFFER = "call_offer"
    CALL_ANSWER = "call_answer"
    CALL_END = "call_end"
    ICE_CANDIDATE = "ice_candidate"
    CALL_ICE = "call_ice"
    CALL_HANGUP = "call_hangup"
    CALL_PING = "call_ping"


class WSMessage(BaseModel):
    """Base WebSocket message."""
    type: WSMessageType
    payload: dict = Field(default_factory=dict)
    request_id: str | None = None  # For request-response matching
