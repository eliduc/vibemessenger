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
Push notification service using Web Push.

v3.2.3 - Added subscription cleanup on 404/410 errors
"""
import json
import logging
from pathlib import Path
from dataclasses import dataclass
from pywebpush import webpush, WebPushException
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PushResult:
    """Result of push notification attempt."""
    success: bool
    should_remove: bool = False  # True if subscription is invalid (404/410)
    error: str | None = None


class PushService:
    def __init__(self):
        self.vapid_private_key = None
        self.vapid_public_key = settings.vapid_public_key
        self.vapid_email = settings.vapid_email
        self._load_private_key()
    
    def _load_private_key(self):
        """Load VAPID private key from file."""
        key_path = settings.vapid_private_key_file
        if key_path and Path(key_path).exists():
            # pywebpush accepts file path directly
            self.vapid_private_key = key_path
            logger.info(f"VAPID private key path set: {key_path}")
        else:
            logger.warning(f"VAPID private key file not found: {key_path}")
    
    def send_push(self, subscription_info: dict, payload: dict) -> PushResult:
        """
        Send push notification to a subscription.
        
        Returns:
            PushResult with success status and whether subscription should be removed.
        """
        if not self.vapid_private_key:
            logger.error("VAPID private key not configured")
            return PushResult(success=False, error="VAPID not configured")
        
        try:
            webpush(
                subscription_info=subscription_info,
                data=json.dumps(payload),
                vapid_private_key=self.vapid_private_key,
                vapid_claims={
                    "sub": self.vapid_email
                }
            )
            logger.info("Push sent successfully")
            return PushResult(success=True)
        except WebPushException as e:
            logger.error(f"Push failed: {e}")
            # 404 = Not Found, 410 = Gone - subscription is invalid
            if e.response and e.response.status_code in (404, 410):
                logger.info(f"Subscription expired/invalid (HTTP {e.response.status_code}), marking for removal")
                return PushResult(success=False, should_remove=True, error=f"Subscription invalid ({e.response.status_code})")
            return PushResult(success=False, error=str(e))
        except Exception as e:
            logger.error(f"Push error: {e}")
            return PushResult(success=False, error=str(e))
    
    def send_call_notification(self, subscription_info: dict, caller_name: str, caller_id: str) -> PushResult:
        """Send incoming call notification."""
        payload = {
            "title": "Incoming Call",
            "body": f"{caller_name} is calling...",
            "type": "call",
            "icon": "/icon-192.png",
            "badge": "/badge-96.png",
            "tag": f"call-{caller_id}",
            "data": {
                "type": "call",
                "caller_id": caller_id,
                "caller_name": caller_name
            }
        }
        return self.send_push(subscription_info, payload)
    
    def send_message_notification(self, subscription_info: dict, sender_name: str, message_preview: str) -> PushResult:
        """Send new message notification."""
        payload = {
            "title": sender_name,
            "body": message_preview[:100],
            "type": "message",
            "icon": "/icon-192.png",
            "badge": "/badge-96.png",
            "tag": f"message-{sender_name}",
            "data": {
                "type": "message",
                "sender_name": sender_name
            }
        }
        return self.send_push(subscription_info, payload)
    
    def send_group_invite_notification(self, subscription_info: dict, inviter_name: str, group_name: str, group_id: str) -> PushResult:
        """Send group invite notification."""
        payload = {
            "title": "Group invitation",
            "body": f"{inviter_name} invites you to group «{group_name}»",
            "type": "group_invite",
            "icon": "/icon-192.png",
            "badge": "/badge-96.png",
            "tag": f"invite-{group_id}",
            "data": {
                "type": "group_invite",
                "inviter_name": inviter_name,
                "group_name": group_name,
                "group_id": group_id
            }
        }
        return self.send_push(subscription_info, payload)
    
    def send_group_message_notification(self, subscription_info: dict, sender_name: str, group_name: str, message_preview: str) -> PushResult:
        """Send group message notification."""
        payload = {
            "title": group_name,
            "body": f"{sender_name}: {message_preview[:80]}",
            "type": "group_message",
            "icon": "/icon-192.png",
            "badge": "/badge-96.png",
            "tag": f"group-message-{group_name}",
            "data": {
                "type": "group_message",
                "sender_name": sender_name,
                "group_name": group_name
            }
        }
        return self.send_push(subscription_info, payload)
    
    def send_group_deleted_notification(self, subscription_info: dict, owner_name: str, group_name: str, group_id: str) -> PushResult:
        """Send group deleted notification."""
        payload = {
            "title": "Group deleted",
            "body": f"{owner_name} deleted group «{group_name}»",
            "type": "group_deleted",
            "icon": "/icon-192.png",
            "badge": "/badge-96.png",
            "tag": f"group-deleted-{group_id}",
            "data": {
                "type": "group_deleted",
                "owner_name": owner_name,
                "group_name": group_name,
                "group_id": group_id
            }
        }
        return self.send_push(subscription_info, payload)


# Singleton instance
push_service = PushService()
