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
Deleting messages without leaving debris behind.

КАО#379. Two admin endpoints removed messages with a raw Core delete
(`Message.__table__.delete().where(...)`):

  * DELETE /admin/messages/by-user/{user_id}
  * DELETE /admin/messages/batch

Only three tables are protected by a real foreign key to `messages` — message_reactions,
saved_messages and message_user_deletions, all ON DELETE CASCADE. Everything else that
points at a message does so with NO foreign key at all, so a raw delete leaves it dangling:

  * pinned_messages.message_id  - and this one is user-visible and unrepairable through the API.
    The pin-limit check counts PinnedMessage rows without joining messages, so a dangling pin
    permanently consumes one of the five slots; and unpin_message loads the Message first, so it
    404s and the pin can never be removed. The chat then reports "Maximum 5 pinned messages
    reached" while displaying fewer.
  * favorite_messages.message_id - a bookmark pointing at nothing.
  * polls.message_id            - a poll whose message is gone; poll_votes cascade from polls, not
    from messages, so the votes survive too.
  * messages.reply_to_id        - a surviving reply quotes a message that no longer exists, and for
    channels the comment counter groups on this column, so it counts comments under a deleted post.

file_metadata.message_id IS a foreign key, but ON DELETE **SET NULL**, and the file garbage
collector only reclaims rows with is_attached = False. A raw delete therefore nulls the link while
leaving is_attached = True, so the row and its encrypted blob become permanently invisible to the
collector and keep counting against the owner's quota. Flipping the flag hands them to the GC
instead, which unlinks on its own schedule - deliberately NOT inline, because a file removed by a
transaction that later rolls back is unrecoverable.

The ordering matters: every child keyed on a message id must go BEFORE the messages themselves,
otherwise the id set no longer exists and the cleanup cannot even be expressed.

This mirrors, statement for statement, the SQL that was verified against the live databases when the
accumulated orphans were cleaned up (KAO/ghostclean.sql).
"""
import logging

from sqlalchemy import delete as sa_delete, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.message import Message, PinnedMessage

logger = logging.getLogger(__name__)


async def purge_messages(db: AsyncSession, message_ids: list[str]) -> dict:
    """Delete messages and every row that references them. Does NOT commit.

    The caller owns the transaction, so this composes with whatever else the endpoint is doing.
    """
    if not message_ids:
        return {"messages": 0, "pins": 0, "favourites": 0, "polls": 0, "replies_unlinked": 0, "files_detached": 0}

    # Imported here: FileMetadata is declared twice in this codebase (app/models/file.py has user_id,
    # app/models/message.py does not) and only this one is the uploads table.
    from app.models.file import FileMetadata
    from app.models.poll import FavoriteMessage, Poll

    # 1. A surviving message must not quote one that is about to disappear.
    replies = await db.execute(
        sa_update(Message)
        .where(Message.reply_to_id.in_(message_ids), ~Message.id.in_(message_ids))
        .values(reply_to_id=None)
    )

    # 2. Hand the attachments to the garbage collector instead of stranding them.
    files = await db.execute(
        sa_update(FileMetadata)
        .where(FileMetadata.message_id.in_(message_ids))
        .values(is_attached=False)
    )

    # 3. Everything keyed on a message id, BEFORE the messages go.
    pins = await db.execute(sa_delete(PinnedMessage).where(PinnedMessage.message_id.in_(message_ids)))
    favs = await db.execute(sa_delete(FavoriteMessage).where(FavoriteMessage.message_id.in_(message_ids)))
    polls = await db.execute(sa_delete(Poll).where(Poll.message_id.in_(message_ids)))

    # 4. The messages themselves. message_reactions / saved_messages / message_user_deletions are real
    #    foreign keys with ON DELETE CASCADE and go with them by design.
    msgs = await db.execute(sa_delete(Message).where(Message.id.in_(message_ids)))

    result = {
        "messages": msgs.rowcount or 0,
        "pins": pins.rowcount or 0,
        "favourites": favs.rowcount or 0,
        "polls": polls.rowcount or 0,
        "replies_unlinked": replies.rowcount or 0,
        "files_detached": files.rowcount or 0,
    }
    logger.info(f"[purge-messages] {result}")
    return result
