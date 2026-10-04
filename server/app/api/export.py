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
Export API endpoints.
"""
from datetime import datetime
from typing import Optional, List
from uuid import uuid4
import json
import html

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.models.message import Message
from app.models.group import Group, GroupMember
from app.models.user import User
from app.models.file import FileMetadata
from app.api.auth import get_current_user_id
import re

router = APIRouter(prefix="/export", tags=["export"])


def _safe_filename(s: str) -> str:
    """КАО#247 (#26): sanitize a user-controlled name before embedding it in a Content-Disposition
    filename — strips CR/LF/quotes/backslash/semicolon and collapses anything outside a safe charset,
    preventing header injection / response splitting via group names or display names."""
    s = re.sub(r'[\r\n"\\;]', '', s or '')
    s = re.sub(r'[^\w.\- ]', '_', s, flags=re.UNICODE)
    s = s.strip()[:64]
    return s or 'chat'


class ExportRequest(BaseModel):
    """Export request parameters."""
    format: str = "json"  # json or html
    include_media: bool = False


async def get_current_user(user_id: str = Depends(get_current_user_id), db: AsyncSession = Depends(get_db)) -> User:
    """Get current user from database."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_user_name(user_id: str, db: AsyncSession) -> str:
    """Get username by ID."""
    result = await db.execute(select(User.username).where(User.id == user_id))
    row = result.first()
    return row[0] if row else "Unknown"


async def get_chat_messages(
    user_id: str, 
    partner_id: str, 
    db: AsyncSession,
    include_media: bool = False
) -> List[dict]:
    """Get all messages for a direct chat."""
    result = await db.execute(
        select(Message).where(
            or_(
                and_(Message.sender_id == user_id, Message.recipient_id == partner_id),
                and_(Message.sender_id == partner_id, Message.recipient_id == user_id)
            )
        ).order_by(Message.created_at.asc())
    )
    messages = result.scalars().all()
    
    export_messages = []
    for msg in messages:
        sender_name = await get_user_name(msg.sender_id, db)
        
        msg_data = {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": sender_name,
            "content": msg.encrypted_payload,  # Base64 encoded
            "type": msg.message_type.value if msg.message_type else "text",
            "timestamp": msg.created_at.isoformat() if msg.created_at else None,
            "is_edited": msg.edited_at is not None,
        }
        
        # Include file info if requested
        if include_media and msg.file_id:
            result = await db.execute(
                # КАО#246 (#35): match on file_id (the UUID stored on the message), not the PK id —
                # the previous FileMetadata.id == msg.file_id never matched, so file metadata never resolved.
                select(FileMetadata).where(FileMetadata.file_id == msg.file_id)
            )
            file_meta = result.scalar_one_or_none()
            if file_meta:
                msg_data["file"] = {
                    "id": file_meta.file_id,
                    "filename": file_meta.original_filename,
                    "size": file_meta.size_bytes,
                    "mime_type": file_meta.mime_type,
                    "download_url": f"/api/v1/files/download/{file_meta.file_id}"
                }
        
        export_messages.append(msg_data)
    
    return export_messages


async def get_group_messages(
    group_id: str,
    db: AsyncSession,
    include_media: bool = False
) -> List[dict]:
    """Get all messages for a group chat."""
    result = await db.execute(
        select(Message).where(Message.group_id == group_id)
        .order_by(Message.created_at.asc())
    )
    messages = result.scalars().all()
    
    export_messages = []
    for msg in messages:
        sender_name = await get_user_name(msg.sender_id, db)
        
        msg_data = {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": sender_name,
            "content": msg.encrypted_payload,
            "type": msg.message_type.value if msg.message_type else "text",
            "timestamp": msg.created_at.isoformat() if msg.created_at else None,
            "is_edited": msg.edited_at is not None,
        }
        
        if include_media and msg.file_id:
            result = await db.execute(
                # КАО#246 (#35): match on file_id (the UUID stored on the message), not the PK id —
                # the previous FileMetadata.id == msg.file_id never matched, so file metadata never resolved.
                select(FileMetadata).where(FileMetadata.file_id == msg.file_id)
            )
            file_meta = result.scalar_one_or_none()
            if file_meta:
                msg_data["file"] = {
                    "id": file_meta.file_id,
                    "filename": file_meta.original_filename,
                    "size": file_meta.size_bytes,
                    "mime_type": file_meta.mime_type,
                    "download_url": f"/api/v1/files/download/{file_meta.file_id}"
                }
        
        export_messages.append(msg_data)
    
    return export_messages


def messages_to_html(messages: List[dict], chat_name: str, export_time: str) -> str:
    """Convert messages to HTML format."""
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat Export: {html.escape(chat_name)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: #075e54;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 5px 0 0; opacity: 0.8; font-size: 14px; }}
        .message {{
            background: white;
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 8px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }}
        .message .sender {{
            font-weight: 600;
            color: #075e54;
            font-size: 14px;
        }}
        .message .time {{
            color: #888;
            font-size: 12px;
            margin-left: 10px;
        }}
        .message .content {{
            margin-top: 6px;
            word-wrap: break-word;
        }}
        .message .file {{
            background: #f0f0f0;
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 8px;
            font-size: 13px;
        }}
        .message .file a {{
            color: #075e54;
            text-decoration: none;
        }}
        .stats {{
            text-align: center;
            color: #888;
            padding: 20px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 {html.escape(chat_name)}</h1>
        <p>Exported on {export_time} • {len(messages)} messages</p>
    </div>
"""
    
    for msg in messages:
        timestamp = ""
        if msg.get("timestamp"):
            try:
                dt = datetime.fromisoformat(msg["timestamp"])
                timestamp = dt.strftime("%Y-%m-%d %H:%M")
            except:
                timestamp = msg["timestamp"]
        
        content = html.escape(msg.get("content", ""))
        
        # Try to decode base64 content for display
        try:
            import base64
            decoded = base64.b64decode(content).decode('utf-8')
            # Try to parse as JSON (might be file info)
            try:
                parsed = json.loads(decoded)
                if isinstance(parsed, dict) and "text" in parsed:
                    content = html.escape(parsed["text"])
                else:
                    content = html.escape(decoded)
            except:
                content = html.escape(decoded)
        except:
            pass
        
        html_content += f"""
    <div class="message">
        <span class="sender">{html.escape(msg.get('sender_name', 'Unknown'))}</span>
        <span class="time">{timestamp}</span>
        <div class="content">{content}</div>
"""
        
        if msg.get("file"):
            file_info = msg["file"]
            html_content += f"""
        <div class="file">
            📎 <a href="{html.escape(file_info.get('download_url', ''))}">{html.escape(file_info.get('filename', 'File'))}</a>
            ({file_info.get('size', 0)} bytes)
        </div>
"""
        
        html_content += "    </div>\n"
    
    html_content += f"""
    <div class="stats">
        Export completed • VibeMessenger
    </div>
</body>
</html>"""
    
    return html_content


@router.post("/chat/{partner_id}")
async def export_chat(
    partner_id: str,
    data: ExportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export a direct chat."""
    # Get partner info
    partner_name = await get_user_name(partner_id, db)
    
    # Get messages
    messages = await get_chat_messages(user.id, partner_id, db, data.include_media)
    
    export_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    if data.format == "html":
        html_content = messages_to_html(messages, f"Chat with {partner_name}", export_time)
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="chat_{_safe_filename(partner_name)}_{datetime.utcnow().strftime("%Y%m%d")}.html"'
            }
        )
    else:
        # JSON format
        export_data = {
            "export_type": "direct_chat",
            "export_time": export_time,
            "chat_partner": {
                "id": partner_id,
                "name": partner_name
            },
            "messages_count": len(messages),
            "messages": messages
        }
        
        return Response(
            content=json.dumps(export_data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="chat_{_safe_filename(partner_name)}_{datetime.utcnow().strftime("%Y%m%d")}.json"'
            }
        )


@router.post("/group/{group_id}")
async def export_group(
    group_id: str,
    data: ExportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export a group chat."""
    # Check if user is member
    result = await db.execute(
        select(GroupMember).where(
            and_(GroupMember.group_id == group_id, GroupMember.user_id == user.id)
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    # Get group info
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Get messages
    messages = await get_group_messages(group_id, db, data.include_media)
    
    export_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    if data.format == "html":
        html_content = messages_to_html(messages, f"Group: {group.name}", export_time)
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="group_{_safe_filename(group.name)}_{datetime.utcnow().strftime("%Y%m%d")}.html"'
            }
        )
    else:
        export_data = {
            "export_type": "group_chat",
            "export_time": export_time,
            "group": {
                "id": group_id,
                "name": group.name,
                "description": group.description
            },
            "messages_count": len(messages),
            "messages": messages
        }
        
        return Response(
            content=json.dumps(export_data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="group_{_safe_filename(group.name)}_{datetime.utcnow().strftime("%Y%m%d")}.json"'
            }
        )


@router.post("/all")
async def export_all_chats(
    data: ExportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export all user's chats."""
    all_exports = []
    
    # Get all direct chats (find unique partners)
    result = await db.execute(
        select(Message.recipient_id).where(Message.sender_id == user.id).distinct()
    )
    sent_to = [r[0] for r in result.all() if r[0]]
    
    result = await db.execute(
        select(Message.sender_id).where(Message.recipient_id == user.id).distinct()
    )
    received_from = [r[0] for r in result.all() if r[0]]
    
    partners = list(set(sent_to + received_from))
    
    # Export each direct chat
    for partner_id in partners:
        partner_name = await get_user_name(partner_id, db)
        messages = await get_chat_messages(user.id, partner_id, db, data.include_media)
        
        all_exports.append({
            "type": "direct_chat",
            "partner": {
                "id": partner_id,
                "name": partner_name
            },
            "messages_count": len(messages),
            "messages": messages
        })
    
    # Get all group chats
    result = await db.execute(
        select(GroupMember).where(GroupMember.user_id == user.id)
    )
    memberships = result.scalars().all()
    
    for membership in memberships:
        result = await db.execute(select(Group).where(Group.id == membership.group_id))
        group = result.scalar_one_or_none()
        if not group:
            continue
        
        messages = await get_group_messages(group.id, db, data.include_media)
        
        all_exports.append({
            "type": "group_chat",
            "group": {
                "id": group.id,
                "name": group.name,
                "description": group.description
            },
            "messages_count": len(messages),
            "messages": messages
        })
    
    export_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    if data.format == "html":
        # Create combined HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>All Chats Export</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .main-header {{
            background: #075e54;
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .chat-section {{
            background: white;
            border-radius: 10px;
            margin-bottom: 30px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .chat-header {{
            background: #128c7e;
            color: white;
            padding: 15px 20px;
        }}
        .chat-header h2 {{ margin: 0; font-size: 18px; }}
        .message {{
            padding: 12px 20px;
            border-bottom: 1px solid #f0f0f0;
        }}
        .message:last-child {{ border-bottom: none; }}
        .message .sender {{ font-weight: 600; color: #075e54; }}
        .message .time {{ color: #888; font-size: 12px; margin-left: 10px; }}
        .message .content {{ margin-top: 6px; }}
    </style>
</head>
<body>
    <div class="main-header">
        <h1>📱 Complete Chat Export</h1>
        <p>Exported on {export_time}</p>
        <p>{len(all_exports)} chats • {sum(e['messages_count'] for e in all_exports)} total messages</p>
    </div>
"""
        
        for export in all_exports:
            if export["type"] == "direct_chat":
                chat_name = f"Chat with {export['partner']['name']}"
            else:
                chat_name = f"Group: {export['group']['name']}"
            
            html_content += f"""
    <div class="chat-section">
        <div class="chat-header">
            <h2>{html.escape(chat_name)} ({export['messages_count']} messages)</h2>
        </div>
"""
            for msg in export["messages"][:100]:  # Limit to 100 per chat in combined view
                timestamp = ""
                if msg.get("timestamp"):
                    try:
                        dt = datetime.fromisoformat(msg["timestamp"])
                        timestamp = dt.strftime("%m-%d %H:%M")
                    except:
                        pass
                
                content = msg.get("content", "")[:200]  # Truncate
                
                html_content += f"""
        <div class="message">
            <span class="sender">{html.escape(msg.get('sender_name', ''))}</span>
            <span class="time">{timestamp}</span>
            <div class="content">{html.escape(content)}</div>
        </div>
"""
            
            if export["messages_count"] > 100:
                html_content += f"""
        <div class="message" style="text-align: center; color: #888;">
            ... and {export['messages_count'] - 100} more messages
        </div>
"""
            
            html_content += "    </div>\n"
        
        html_content += """
</body>
</html>"""
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="all_chats_{datetime.utcnow().strftime("%Y%m%d")}.html"'
            }
        )
    else:
        export_data = {
            "export_type": "all_chats",
            "export_time": export_time,
            "user_id": user.id,
            "chats_count": len(all_exports),
            "total_messages": sum(e["messages_count"] for e in all_exports),
            "chats": all_exports
        }
        
        return Response(
            content=json.dumps(export_data, indent=2, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="all_chats_{datetime.utcnow().strftime("%Y%m%d")}.json"'
            }
        )
