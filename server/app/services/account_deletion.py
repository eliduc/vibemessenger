"""
Account deletion - the single implementation, shared by self-service and admin.

КАО#378. There used to be two ways to delete a user and only one of them was correct:

  * `DELETE /auth/me` (КАО#350) does it properly - claim a tombstone name up front, hand over owned groups,
    drop only undelivered DIRECT messages, destroy every credential, purge the rows that are private to the
    user, anonymise the row, commit, and only then touch the filesystem.

  * `DELETE /admin/users/{id}` did `await db.delete(user)`. That does NOT fail: `key_bundles`,
    `refresh_tokens` and `webauthn_credentials` are relationships with cascade="all, delete-orphan", and
    `push_subscriptions` / `file_metadata` are ON DELETE CASCADE at the database level. So it SUCCEEDS every
    time and silently corrupts, because ten further tables reference users with no foreign key at all.
    Measured on the production database before this fix: 124 messages and 19 groups referenced users that no
    longer existed, while orphan key_bundles / refresh_tokens / webauthn / file_metadata were all 0 - which
    is exactly the signature of a delete that cascaded the FK-backed tables and left everything else behind.
    Two further consequences: the username was freed instantly, so the other party's history lost its sender
    entirely rather than showing a deleted account; and the file BYTES were orphaned for ever, because the
    `file_metadata` rows cascaded away and nothing unlinks a file you can no longer find.

The row deliberately survives as a tombstone. Ten tables reference users WITHOUT a foreign key, so dropping
it would leave dangling ids and other people's history would start rendering "Unknown".

INVARIANT: this function owns its transaction from end to end. It commits, and its fail-clean path calls
db.rollback(). Callers must therefore hold no uncommitted work of their own, and - because rollback() expires
every object in the identity map regardless of expire_on_commit - must NOT hold an ORM instance across the
call. That is why it takes a user_id and loads the row itself.
"""
import logging
import os
import secrets as _secrets

from sqlalchemy import select, and_, delete as sa_delete, or_ as sa_or, update as sa_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.models.user import User, KeyBundle, RefreshToken, PushSubscription, WebAuthnCredential
from app.models.message import (
    Message, MessageStatus, MessageReaction, MessageUserDeletion, PinnedMessage, SavedMessage,
)
from app.models.group import Group, GroupMember, ROLE_HIERARCHY
from app.models.poll import FavoriteMessage, PollVote
from app.models.audit import AuditEventType, AuditSeverity
from app.services.audit_service import audit_service as audit
from app.services.auth_service import auth_service
from app.services.websocket_manager import ws_manager

logger = logging.getLogger(__name__)

AVATAR_DIR = "/app/data/avatars"


class AccountDeletionError(Exception):
    """The account could not be deleted and has been left completely intact."""


class AlreadyDeleted(Exception):
    """The target is already a tombstone; nothing to do."""


async def purge_user_account(
    db: AsyncSession,
    user_id: str,
    *,
    actor_id: str,
    actor_username: str | None = None,
    request: Request | None = None,
    reason: str = "account deleted by its owner",
) -> dict:
    """Destroy an account, leaving a tombstone. See the module docstring for the invariant.

    Takes a user_id, not a User: the fail-clean rollback expires the identity map, so a caller holding an
    ORM instance across this call would get MissingGreenlet on its next attribute read.
    """
    # КАО#378: MutedChat / UserBlock live in an API module; import function-locally to keep this a leaf
    # module and avoid the app.api.auth -> app.api.user_settings -> app.api.auth cycle.
    from app.api.user_settings import MutedChat, UserBlock
    # There are TWO declarative classes named FileMetadata (app/models/file.py, app/models/message.py) and
    # only this one has a user_id column. Import it here, explicitly, so the other cannot satisfy the name.
    from app.models.file import FileMetadata

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise AccountDeletionError("User not found")
    if user.is_active is False and str(user.username or "").startswith("deleted_"):
        # Re-purging a tombstone would draw a NEW random name, invalidating the one already written to the
        # audit trail, and would emit a second USER_DELETED for an account that is already gone.
        raise AlreadyDeleted(user.username)

    target_username = user.username

    # ---- 1b. KAO#359: claim the tombstone identity BEFORE destroying anything ---------------------
    # The previous shape assigned the name last and "retried" inside an IntegrityError handler, which was
    # incoherent: db.rollback() undoes the WHOLE transaction (key bundles, tokens, group transfers all
    # come back), so the retry committed nothing but a rename - leaving an account that merely LOOKS
    # deleted while it can still log in and still owns its groups, and the endpoint then unlinked the
    # user's files anyway and answered 200. Resolve the only realistically-colliding values up front,
    # with a flush, while a failure is still free: nothing has been destroyed yet.
    tombstone = None
    for _attempt in range(4):
        candidate = _secrets.token_hex(6)
        clash = (await db.execute(select(User).where(sa_or(
            User.username == f"deleted_{candidate}",
            User.display_name == f"Deleted account {candidate}",
        )))).first()
        if clash is None:
            tombstone = candidate
            break
    if tombstone is None:
        # 4 independent 48-bit draws all colliding is not a real condition; treat it as a server fault
        # rather than half-deleting the account.
        logger.error(f"[delete-account] could not allocate a tombstone name for {user_id}")
        raise AccountDeletionError("Could not complete deletion, please try again")

    # ---- 2. groups: hand over the ones they own, drop the ones nobody else is in -----------------
    owned = (await db.execute(
        select(GroupMember).where(and_(GroupMember.user_id == user_id, GroupMember.role == "owner"))
    )).scalars().all()
    groups_transferred = 0
    groups_deleted = 0
    for membership in owned:
        others = (await db.execute(
            select(GroupMember)
            .where(and_(GroupMember.group_id == membership.group_id, GroupMember.user_id != user_id))
            .order_by(GroupMember.joined_at.asc())
        )).scalars().all()
        # KAO#354: rank by ROLE_HIERARCHY (owner>admin>moderator>member>subscriber) and NEVER hand a
        # channel to a read-only `subscriber` - taking others[0] (merely the oldest row) could promote a
        # follower straight to owner of a channel they were only subscribed to.
        eligible = [m for m in others if ROLE_HIERARCHY.get(m.role, 0) > ROLE_HIERARCHY.get("subscriber", 0)]
        if eligible:
            heir = max(eligible, key=lambda m: (ROLE_HIERARCHY.get(m.role, 0), -(m.joined_at.timestamp() if m.joined_at else 0)))
        else:
            heir = None
        if heir is not None:
            heir.role = "owner"
            grp = (await db.execute(
                select(Group).where(Group.id == membership.group_id)
            )).scalar_one_or_none()
            if grp:
                grp.created_by = heir.user_id
            groups_transferred += 1
        else:
            # nobody eligible is left (empty, or subscribers only) - the group cannot outlive its owner
            await db.execute(sa_delete(Group).where(Group.id == membership.group_id))
            await db.execute(sa_delete(GroupMember).where(GroupMember.group_id == membership.group_id))
            groups_deleted += 1
    await db.execute(sa_delete(GroupMember).where(GroupMember.user_id == user_id))

    # ---- 3. messages of theirs that never reached anyone ----------------------------------------
    # KAO#355 (critical): scope this to DIRECT messages. /messages/ack only ever matches rows with
    # `recipient_id == user_id` (messages.py), and a GROUP message has recipient_id NULL - so a group
    # message can never leave status PENDING no matter how many members read it years ago. Without the
    # group_id filter this statement deleted EVERY group message the user had ever sent, wiping other
    # people's group history - the exact opposite of what this endpoint promises.
    pending = await db.execute(sa_delete(Message).where(and_(
        Message.sender_id == user_id,
        Message.group_id.is_(None),
        Message.status == MessageStatus.PENDING,
    )))

    # ---- 4. destroy every credential and key ----------------------------------------------------
    # key_bundles / refresh_tokens are FK ON DELETE NO ACTION, so they must be removed explicitly -
    # which is also precisely what makes the account unusable: with no bundle nobody can start a
    # session, and with no refresh token every device is signed out.
    await db.execute(sa_delete(KeyBundle).where(KeyBundle.user_id == user_id))
    await db.execute(sa_delete(RefreshToken).where(RefreshToken.user_id == user_id))
    await db.execute(sa_delete(PushSubscription).where(PushSubscription.user_id == user_id))
    await db.execute(sa_delete(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id))

    # KAO#356: rows that belong to THIS user alone. They would normally go via ON DELETE CASCADE, but the
    # user row deliberately survives as a tombstone, so the cascade never fires and they would linger:
    # who they muted, who they blocked, what they favourited/saved, their reactions and their pins.
    await db.execute(sa_delete(MutedChat).where(MutedChat.user_id == user_id))
    await db.execute(sa_delete(UserBlock).where(sa_or(
        UserBlock.blocker_id == user_id, UserBlock.blocked_id == user_id,
    )))
    await db.execute(sa_delete(FavoriteMessage).where(FavoriteMessage.user_id == user_id))
    await db.execute(sa_delete(SavedMessage).where(SavedMessage.user_id == user_id))
    await db.execute(sa_delete(MessageReaction).where(MessageReaction.user_id == user_id))
    await db.execute(sa_delete(MessageUserDeletion).where(MessageUserDeletion.user_id == user_id))
    # KAO#361: clear the denormalised flag BEFORE dropping the pin rows, otherwise the message keeps
    # is_pinned=True while the pinned-messages list is empty - a broken badge inflicted on the OTHER
    # members, not on the person leaving. uq_pinned_chat_message guarantees one pin row per message per
    # chat, so no other pin can still be justifying the flag.
    _pinned_ids = [r[0] for r in (await db.execute(
        select(PinnedMessage.message_id).where(PinnedMessage.pinned_by == user_id)
    )).all()]
    if _pinned_ids:
        await db.execute(
            sa_update(Message).where(Message.id.in_(_pinned_ids)).values(is_pinned=False)
        )
    await db.execute(sa_delete(PinnedMessage).where(PinnedMessage.pinned_by == user_id))
    # KAO#360: poll votes are the exact analogue of a reaction - a personal choice attached to shared
    # content - and poll_votes.user_id has no foreign key, so nothing else will ever remove them. For a
    # non-anonymous poll the voter ids are returned to every participant, and the tombstone keeps the same
    # id the retained messages carry, so the vote would stay attributable forever; for an anonymous poll
    # the server would keep the identity-to-choice link indefinitely. Tallies simply recompute.
    await db.execute(sa_delete(PollVote).where(PollVote.user_id == user_id))

    # uploaded files: the rows and the bytes. On disk a file is "<file_id>.<ext>" under UPLOAD_DIR.
    # KAO#351: only COLLECT the paths here. Deleting bytes before the commit was unsafe: get_db() rolls
    # the transaction back on any later exception (e.g. an IntegrityError while anonymising), which would
    # leave the account fully intact but its files already erased from disk - destruction without the
    # deletion the user asked for. The unlink happens after the commit instead, so the only possible
    # residue is orphaned bytes whose rows are already gone (harmless, and reclaimable by the file GC).
    doomed_files = []
    try:
        from app.api.files import UPLOAD_DIR
        rows = (await db.execute(
            select(FileMetadata).where(FileMetadata.user_id == user_id)
        )).scalars().all()
        for f in rows:
            name = f"{f.file_id}.{f.extension}" if f.extension else str(f.file_id)
            doomed_files.append(os.path.join(UPLOAD_DIR, os.path.basename(name)))
        await db.execute(sa_delete(FileMetadata).where(FileMetadata.user_id == user_id))
    except Exception as e:
        logger.warning(f"[delete-account] file row cleanup skipped: {e}")

    if user.avatar_url:
        doomed_files.append(os.path.join(AVATAR_DIR, os.path.basename(user.avatar_url)))

    # ---- 5. anonymise the row (tombstone for the ten FK-less tables) ------------------------------
    # KAO#357: the tombstone comes from FRESH ENTROPY, not from the user id. Both columns are UNIQUE and
    # `GET /auth/user/{name}` hands out any user's id, so a name derived from the id was predictable and
    # could be pre-registered by anyone to make the victim's own deletion fail forever. KAO#359: the value
    # was already claimed above, before anything was destroyed.
    short = tombstone
    user.username = f"deleted_{short}"
    user.display_name = f"Deleted account {short}"   # display_name is UNIQUE - keep it unique
    user.password_hash = auth_service.hash_password(_secrets.token_urlsafe(32))
    user.avatar_url = None
    user.phone_hash = None
    user.device_id = None
    user.push_token = None
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_last_counter = None
    user.recovery_codes = None
    user.self_encryption_key = None
    user.is_active = False
    user.is_verified = False

    try:
        # KAO#362: audit.log_event() ends with db.flush(), and the session runs with autoflush=False - so
        # THAT flush is what actually emits the tombstone UPDATE. With log_event outside this block a
        # unique violation raised before the try, making the fail-clean handler below unreachable dead
        # code (the request still ended safely, but via get_db's generic rollback and an opaque 500
        # instead of the intended retryable 503). Keep the flushing statement inside the guard.
        # КАО#378: name the ACTOR and the TARGET separately - for a self-service deletion they are the
        # same, for an admin deletion they are not, and the old row recorded the victim as the actor with a
        # hardcoded "by its owner". `details` is also a dict now: log_event declares Optional[dict] and
        # json.dumps() it, so an f-string was being stored as a JSON-quoted string instead of an object.
        await audit.log_event(
            db=db, event_type=AuditEventType.USER_DELETED, severity=AuditSeverity.WARNING,
            user_id=actor_id, username=actor_username,
            target_user_id=user_id, target_resource_id=user_id, target_resource_type="user",
            request=request,
            details={
                "reason": reason,
                "deleted_username": target_username,
                "tombstone": f"deleted_{short}",
                "self_service": actor_id == user_id,
                "groups_transferred": groups_transferred,
                "groups_deleted": groups_deleted,
            },
        )
        await db.commit()
    except IntegrityError as e:
        # KAO#359: fail CLEANLY. Everything above is one transaction, so this rollback restores the account
        # exactly as it was - no keys destroyed, no groups reassigned, nothing renamed. The one thing that
        # must not happen now is touching the filesystem, so we return before step 6: a failed deletion
        # must never cost the user their files. The client can simply try again (a fresh name is drawn).
        await db.rollback()
        logger.error(f"[delete-account] commit failed for {user_id}, account left intact: {e}")
        raise AccountDeletionError("Could not complete deletion, please try again")

    # ---- 6. only NOW touch the filesystem: the deletion is durable, so losing bytes is intended ----
    files_removed = 0
    for path in doomed_files:
        try:
            if os.path.isfile(path):
                os.remove(path)
                files_removed += 1
        except OSError as e:
            logger.warning(f"[delete-account] could not unlink {path}: {e}")

    # ---- 7. kick every live socket ---------------------------------------------------------------
    try:
        await ws_manager.disconnect_user(user_id, "Account deleted")
    except Exception as e:
        # KAO#353: never silent - this step failing means a deleted identity keeps a live socket.
        logger.error(f"[delete-account] could not disconnect sockets for {user_id}: {e}")

    return {
        "status": "deleted",
        "tombstone_username": user.username,
        "pending_messages_removed": pending.rowcount or 0,
        "groups_transferred": groups_transferred,
        "groups_deleted": groups_deleted,
        "files_removed": files_removed,
    }
