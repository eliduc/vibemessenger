"""
File upload/download API endpoints with persistent storage and quotas.
"""
import os
import uuid
import aiofiles
import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, and_, func, delete

from app.database import get_db
from app.api.auth import get_current_user_id
from app.config import settings
from app.models.message import Message
from app.models.group import GroupMember
from app.models.file import FileMetadata, UserStorageStats
from app.rate_limiter import user_limiter, RATE_LIMIT_UPLOAD

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["Files"])

# Create uploads directory (persistent storage)
UPLOAD_DIR = "/app/data/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ============== Configuration ==============
# All limits are centralized in app.config.settings

from app.config import settings as app_settings

# Max file size from config
MAX_FILE_SIZE = app_settings.max_file_size

# Per-user storage quota from config
USER_STORAGE_QUOTA = app_settings.user_storage_quota

# Unattached file TTL from config
UNATTACHED_FILE_TTL_HOURS = app_settings.unattached_file_ttl_hours

# Allowed extensions
ALLOWED_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'gif', 'webp',  # Images
    'pdf', 'doc', 'docx', 'txt',  # Documents
    'mp3', 'wav', 'ogg',  # Audio
    'mp4', 'webm',  # Video
    'zip', 'rar', '7z',  # Archives
    'enc',  # v3.11.9: E2EE encrypted files
}


def get_extension(filename: str) -> str:
    """Get file extension."""
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower()
    return ''


async def get_user_storage_used(db: AsyncSession, user_id: str) -> int:
    """Get total bytes used by a user."""
    result = await db.execute(
        select(func.coalesce(func.sum(FileMetadata.size_bytes), 0)).where(
            FileMetadata.user_id == user_id
        )
    )
    return result.scalar() or 0


async def check_user_quota(db: AsyncSession, user_id: str, new_file_size: int) -> tuple[bool, int, int]:
    """
    Check if user has enough quota for new file.
    
    Returns: (has_quota, used_bytes, quota_bytes)
    """
    used = await get_user_storage_used(db, user_id)
    return (used + new_file_size) <= USER_STORAGE_QUOTA, used, USER_STORAGE_QUOTA


@router.get("/storage")
async def get_storage_stats(
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get user's storage statistics."""
    used = await get_user_storage_used(db, user_id)
    
    # Count files
    count_result = await db.execute(
        select(func.count(FileMetadata.id)).where(
            FileMetadata.user_id == user_id
        )
    )
    file_count = count_result.scalar() or 0
    
    return UserStorageStats(
        used_bytes=used,
        quota_bytes=USER_STORAGE_QUOTA,
        file_count=file_count,
        used_percent=round((used / USER_STORAGE_QUOTA) * 100, 2) if USER_STORAGE_QUOTA > 0 else 0
    )


@router.post("/upload")
@user_limiter.limit(RATE_LIMIT_UPLOAD)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a file.
    Returns file_id to use in messages.
    
    Enforces:
    - File type whitelist
    - Max file size (10MB)
    - Per-user storage quota (100MB)
    Rate limited: 10 requests per minute per user.
    """
    # Check extension
    ext = get_extension(file.filename or '')
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    
    # Generate unique filename
    file_id = str(uuid.uuid4())
    safe_filename = f"{file_id}.{ext}" if ext else file_id
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Read and write file in chunks with size check
    total_size = 0
    chunk_size = 1024 * 1024  # 1MB chunks
    
    try:
        async with aiofiles.open(file_path, 'wb') as f:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                
                total_size += len(chunk)
                
                # Check size limit DURING upload
                if total_size > MAX_FILE_SIZE:
                    await f.close()
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File too large. Max size: {MAX_FILE_SIZE // 1024 // 1024}MB"
                    )
                
                await f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        logger.exception(f"File upload error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save file"
        )
    
    # Check quota AFTER writing (we know the real size now)
    has_quota, used, quota = await check_user_quota(db, user_id, total_size)
    if not has_quota:
        # Remove file and reject
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Storage quota exceeded. Used: {used // 1024 // 1024}MB, Quota: {quota // 1024 // 1024}MB"
        )
    
    # Save metadata to database
    file_metadata = FileMetadata(
        user_id=user_id,
        file_id=file_id,
        original_filename=file.filename,
        extension=ext,
        mime_type=file.content_type,
        size_bytes=total_size,
        is_attached=False,
        uploaded_at=datetime.now(timezone.utc),
    )
    db.add(file_metadata)
    await db.commit()
    
    return {
        "file_id": file_id,
        "filename": file.filename,
        "size": total_size,
        "content_type": file.content_type,
        "extension": ext,
    }


async def get_file_owner(db: AsyncSession, file_id: str) -> str | None:
    """Get file owner user_id from database."""
    result = await db.execute(
        select(FileMetadata.user_id).where(FileMetadata.file_id == file_id)
    )
    return result.scalar_one_or_none()


async def check_file_access(file_id: str, user_id: str, db: AsyncSession) -> bool:
    """
    Check if user has access to the file.
    Access is granted if:
    1. User uploaded the file, OR
    2. File is attached to a message where user is sender/recipient, OR
    3. File is attached to a group message where user is a member
    """
    # Check if user is the uploader (from DB now)
    owner_id = await get_file_owner(db, file_id)
    if owner_id == user_id:
        return True
    
    # Check if file is in a message the user can access
    # Direct message: user is sender or recipient
    direct_msg = await db.execute(
        select(Message).where(
            and_(
                Message.file_id == file_id,
                Message.group_id.is_(None),
                or_(
                    Message.sender_id == user_id,
                    Message.recipient_id == user_id
                )
            )
        )
    )
    if direct_msg.first():
        return True
    
    # Group message: user is member of the group
    group_msg = await db.execute(
        select(Message).where(
            and_(
                Message.file_id == file_id,
                Message.group_id.isnot(None)
            )
        )
    )
    msg_row = group_msg.first()
    if msg_row:
        msg = msg_row[0]
        if msg.group_id:
            # Check if user is member of this group
            member = await db.execute(
                select(GroupMember).where(
                    and_(
                        GroupMember.group_id == msg.group_id,
                        GroupMember.user_id == user_id
                    )
                )
            )
            if member.first():
                return True
    
    return False


async def mark_file_attached(db: AsyncSession, file_id: str, message_id: str, owner_id: str | None = None):
    """Mark a file as attached to a message."""
    result = await db.execute(
        select(FileMetadata).where(FileMetadata.file_id == file_id)
    )
    file_meta = result.scalar_one_or_none()
    if file_meta:
        # КАО#007: prevent attaching a file owned by another user (IDOR)
        if owner_id is not None and file_meta.user_id != owner_id:
            raise HTTPException(status_code=403, detail="File does not belong to sender")
        file_meta.is_attached = True
        file_meta.message_id = message_id
        file_meta.attached_at = datetime.now(timezone.utc)
        await db.commit()


@router.get("/download/{file_id}")
async def download_file(
    file_id: str,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Download a file by ID.
    Only accessible to users who have access to the file.
    """
    # Check access
    has_access = await check_file_access(file_id, user_id, db)
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Find file with any extension
    for filename in os.listdir(UPLOAD_DIR):
        if filename.startswith(file_id):
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            # Get original filename from DB
            result = await db.execute(
                select(FileMetadata.original_filename).where(FileMetadata.file_id == file_id)
            )
            original_name = result.scalar_one_or_none() or filename
            
            return FileResponse(
                file_path,
                filename=original_name,
                media_type='application/octet-stream'
            )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found"
    )


@router.get("/info/{file_id}")
async def get_file_info(
    file_id: str,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get file metadata."""
    # Check access
    has_access = await check_file_access(file_id, user_id, db)
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get from DB
    result = await db.execute(
        select(FileMetadata).where(FileMetadata.file_id == file_id)
    )
    file_meta = result.scalar_one_or_none()
    
    if not file_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    return {
        "file_id": file_id,
        "filename": file_meta.original_filename,
        "size": file_meta.size_bytes,
        "extension": file_meta.extension,
        "mime_type": file_meta.mime_type,
        "is_attached": file_meta.is_attached,
        "uploaded_at": file_meta.uploaded_at.isoformat() if file_meta.uploaded_at else None,
    }


@router.delete("/{file_id}")
async def delete_file(
    file_id: str,
    user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a file. Only the uploader can delete.
    """
    # Get file metadata
    result = await db.execute(
        select(FileMetadata).where(FileMetadata.file_id == file_id)
    )
    file_meta = result.scalar_one_or_none()
    
    if not file_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Only uploader can delete
    if file_meta.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the uploader can delete this file"
        )
    
    # Delete physical file
    for filename in os.listdir(UPLOAD_DIR):
        if filename.startswith(file_id):
            file_path = os.path.join(UPLOAD_DIR, filename)
            try:
                os.remove(file_path)
            except OSError as e:
                logger.error(f"Failed to delete file {file_path}: {e}")
    
    # Delete from database
    await db.delete(file_meta)
    await db.commit()
    
    return {"status": "deleted"}


# ============== Garbage Collection ==============

async def cleanup_unattached_files(db: AsyncSession) -> int:
    """
    Delete unattached files older than TTL.
    
    Returns number of files deleted.
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=UNATTACHED_FILE_TTL_HOURS)
    
    # Find old unattached files
    result = await db.execute(
        select(FileMetadata).where(
            and_(
                FileMetadata.is_attached == False,
                FileMetadata.uploaded_at < cutoff_time
            )
        )
    )
    files_to_delete = result.scalars().all()
    
    deleted_count = 0
    for file_meta in files_to_delete:
        # Delete physical file
        for filename in os.listdir(UPLOAD_DIR):
            if filename.startswith(file_meta.file_id):
                file_path = os.path.join(UPLOAD_DIR, filename)
                try:
                    os.remove(file_path)
                    logger.info(f"GC: Deleted orphaned file {file_meta.file_id}")
                except OSError as e:
                    logger.error(f"GC: Failed to delete {file_path}: {e}")
        
        # Delete from database
        await db.delete(file_meta)
        deleted_count += 1
    
    if deleted_count > 0:
        await db.commit()
        logger.info(f"GC: Cleaned up {deleted_count} unattached files")
    
    return deleted_count
