"""
Poll model and related schemas.
"""
from datetime import datetime
from uuid import uuid4
from typing import Optional, List

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field

from app.database import Base, TimestampMixin


# ============== SQLAlchemy Models ==============

class Poll(Base, TimestampMixin):
    """
    Poll/survey in a chat.
    """
    __tablename__ = "polls"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Where the poll belongs
    chat_id = Column(String(36), nullable=True, index=True)  # For direct messages
    group_id = Column(String(36), nullable=True, index=True)  # For group chats
    
    # Creator
    creator_id = Column(String(36), nullable=False, index=True)
    
    # Poll content
    # КАО#230 (SER#18): question/options are stored ENCRYPTED (per-poll key, "e2e:" prefix) so the
    # server is zero-knowledge. Widened from String(500) to Text to fit ciphertext (migration:
    # ALTER TABLE polls ALTER COLUMN question TYPE TEXT). Legacy plaintext rows remain valid.
    question = Column(Text, nullable=False)
    options = Column(JSON, nullable=False)  # List of (encrypted) strings, max 10
    
    # Settings
    is_anonymous = Column(Boolean, default=True)  # Hide who voted for what
    is_multiple = Column(Boolean, default=False)  # Allow multiple choices
    
    # Expiration
    expires_at = Column(DateTime, nullable=True)  # Null = no expiration
    is_closed = Column(Boolean, default=False)  # Manually closed by creator
    
    # Link to message
    message_id = Column(String(36), nullable=True)  # The message containing this poll
    
    # Relationships
    votes = relationship("PollVote", back_populates="poll", cascade="all, delete-orphan")


class PollVote(Base):
    """
    Individual vote on a poll.
    """
    __tablename__ = "poll_votes"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    poll_id = Column(String(36), ForeignKey("polls.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    
    # Which options selected (list of indices for multiple choice)
    selected_options = Column(JSON, nullable=False)  # e.g., [0] or [0, 2, 3]

    voted_at = Column(DateTime, default=datetime.utcnow)

    # КАО#251 (#24): one vote row per (poll, user) — prevents concurrent/duplicate votes from
    # double-counting tallies. Migration dedups then ADDs this constraint.
    __table_args__ = (
        UniqueConstraint('poll_id', 'user_id', name='uq_poll_votes_poll_user'),
    )

    # Relationships
    poll = relationship("Poll", back_populates="votes")


# ============== Pydantic Schemas ==============

class PollOptionResult(BaseModel):
    """Result for a single poll option."""
    index: int
    text: str
    votes: int
    percentage: float
    voters: Optional[List[str]] = None  # Only if not anonymous


class PollCreate(BaseModel):
    """Schema for creating a poll."""
    # КАО#230 (SER#18): max_length raised to fit an encrypted question (a 500-char plaintext
    # question encrypts + base64s to well under 4000 chars). Plaintext questions are unaffected.
    question: str = Field(..., min_length=1, max_length=4000)
    options: List[str] = Field(..., min_items=2, max_items=10)
    is_anonymous: bool = True
    is_multiple: bool = False
    expires_in_minutes: Optional[int] = Field(None, ge=1, le=10080)  # Max 7 days
    
    # Target chat
    chat_id: Optional[str] = None
    group_id: Optional[str] = None


class PollVoteRequest(BaseModel):
    """Schema for voting on a poll."""
    selected_options: List[int] = Field(..., min_items=1)


class PollResponse(BaseModel):
    """Schema for poll response."""
    id: str
    question: str
    options: List[str]
    is_anonymous: bool
    is_multiple: bool
    expires_at: Optional[datetime]
    is_closed: bool
    creator_id: str
    message_id: Optional[str]
    total_votes: int
    results: List[PollOptionResult]
    user_voted: bool
    user_selections: Optional[List[int]] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class FavoriteMessage(Base, TimestampMixin):
    """
    User's favorite/saved messages.
    """
    __tablename__ = "favorite_messages"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    user_id = Column(String(36), nullable=False, index=True)
    message_id = Column(String(36), nullable=False, index=True)
    
    # Cache for quick access (so we don't need to join with messages table)
    chat_id = Column(String(36), nullable=True)  # Direct chat partner ID
    group_id = Column(String(36), nullable=True)
    sender_id = Column(String(36), nullable=False)
    sender_name = Column(String(100), nullable=True)
    # КАО#231 (SER#18 follow-up): widened String(200)→Text to fit a self-ENCRYPTED preview (the
    # client now encryptForSelf's the preview so the server stays zero-knowledge; ciphertext of a
    # 200-char preview exceeds 200). Migration: ALTER TABLE favorite_messages ALTER COLUMN preview_text TYPE TEXT.
    preview_text = Column(Text, nullable=True)  # encrypted-for-self preview (or legacy plaintext)

    # КАО#252 (#36): one favorite row per (user, message) — blocks duplicate favorites from concurrent
    # add / batch-add races. Migration dedups then ADDs this constraint.
    __table_args__ = (
        UniqueConstraint('user_id', 'message_id', name='uq_favorite_user_message'),
    )


# ============== Favorite Schemas ==============

class FavoriteCreate(BaseModel):
    """Schema for adding a favorite."""
    message_id: str
    chat_id: Optional[str] = None
    group_id: Optional[str] = None
    sender_id: str
    sender_name: Optional[str] = None
    preview_text: Optional[str] = None


class FavoriteResponse(BaseModel):
    """Schema for favorite response."""
    id: str
    message_id: str
    chat_id: Optional[str]
    group_id: Optional[str]
    sender_id: str
    sender_name: Optional[str]
    preview_text: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True
