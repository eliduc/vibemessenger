"""
WebSocket connection manager for real-time messaging.
"""
import asyncio
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Callable, Awaitable

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from app.models.message import WSMessage, WSMessageType
from app.config import settings


logger = logging.getLogger(__name__)


@dataclass
class Connection:
    """Represents a WebSocket connection."""
    websocket: WebSocket
    user_id: str
    device_id: str | None = None
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_ping: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WebSocketManager:
    """
    Manages WebSocket connections for all users.

    Features:
    - Multiple connections per user (different devices)
    - Heartbeat monitoring
    - Message routing
    - Online status tracking
    """

    def __init__(self):
        # user_id -> list of connections
        self._connections: dict[str, list[Connection]] = {}

        # Message handlers: type -> handler function
        self._handlers: dict[WSMessageType, Callable] = {}

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        # Heartbeat task
        self._heartbeat_task: asyncio.Task | None = None

    async def start(self):
        """Start the WebSocket manager (heartbeat monitoring)."""
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("WebSocket manager started")

    async def stop(self):
        """Stop the WebSocket manager."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        logger.info("WebSocket manager stopped")

    def register_handler(
        self,
        msg_type: WSMessageType,
        handler: Callable[[Connection, dict], Awaitable[None]]
    ):
        """Register a handler for a message type."""
        self._handlers[msg_type] = handler

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        device_id: str | None = None,
        already_accepted: bool = False
    ) -> Connection:
        """Accept a new WebSocket connection."""
        if not already_accepted:
            await websocket.accept()

        connection = Connection(
            websocket=websocket,
            user_id=user_id,
            device_id=device_id,
        )

        async with self._lock:
            if user_id not in self._connections:
                self._connections[user_id] = []

            # Limit connections per user
            user_connections = self._connections[user_id]
            if len(user_connections) >= settings.ws_max_connections_per_user:
                # Disconnect oldest connection
                oldest = user_connections[0]
                await self._close_connection(oldest, "New connection from same user")
                user_connections.pop(0)

            user_connections.append(connection)

        # Notify contacts about online status
        await self._broadcast_status(user_id, online=True)

        logger.info(f"User {user_id} connected (device: {device_id})")
        return connection

    async def disconnect(self, connection: Connection):
        """Handle WebSocket disconnection."""
        user_id = connection.user_id

        async with self._lock:
            if user_id in self._connections:
                try:
                    self._connections[user_id].remove(connection)
                except ValueError:
                    pass

                # Remove user entry if no connections left
                if not self._connections[user_id]:
                    del self._connections[user_id]
                    # Notify about offline status
                    await self._broadcast_status(user_id, online=False)

        logger.info(f"User {user_id} disconnected")

    async def handle_message(self, connection: Connection, data: str):
        """Process incoming WebSocket message."""
        try:
            msg = WSMessage.model_validate_json(data)
        except ValidationError as e:
            logger.warning(f"Invalid WebSocket message format: {e}")
            await self.send_error(connection, "Invalid message format")
            return

        # Handle ping specially
        if msg.type == WSMessageType.PING:
            connection.last_ping = datetime.now(timezone.utc)
            await self.send_to_connection(
                connection,
                WSMessage(type=WSMessageType.PONG, request_id=msg.request_id)
            )
            return

        # Handle call signaling
        if msg.type in (WSMessageType.CALL_OFFER, WSMessageType.CALL_ANSWER,
                        WSMessageType.CALL_END, WSMessageType.ICE_CANDIDATE,
                        WSMessageType.CALL_PING):
            await self._handle_call_signal(connection, msg)
            return

        # Handle typing indicator
        if msg.type == WSMessageType.TYPING:
            await self._handle_typing(connection, msg)
            return

        # Find and execute handler
        handler = self._handlers.get(msg.type)
        if handler:
            try:
                await handler(connection, msg.payload, msg.request_id)
            except Exception as e:
                logger.exception(f"Error handling {msg.type}: {e}")
                await self.send_error(connection, "An error occurred while processing your request", msg.request_id)
        else:
            await self.send_error(
                connection,
                f"Unknown message type: {msg.type}",
                msg.request_id
            )

    async def send_to_user(
        self,
        user_id: str,
        message: WSMessage,
        exclude_device: str | None = None,
    ) -> bool:
        """Send message to all connections of a user."""
        # Get connections without blocking (dict.get is thread-safe in Python)
        connections = self._connections.get(user_id, [])
        if not connections:
            logger.debug(f"No connections for user {user_id}")
            return False

        # Make a copy to avoid issues if list changes during iteration
        connections = list(connections)
        logger.debug(f"Sending to {user_id}, {len(connections)} connections")
        
        sent = False
        for conn in connections:
            if exclude_device and conn.device_id == exclude_device:
                continue

            try:
                await self.send_to_connection(conn, message)
                sent = True
                logger.debug(f"Sent message to {user_id}")
            except Exception as e:
                logger.warning(f"Failed to send to {user_id}: {e}")

        return sent

    async def send_to_connection(self, connection: Connection, message: WSMessage):
        """Send message to a specific connection."""
        try:
            # Add timeout to prevent hanging on broken connections
            await asyncio.wait_for(
                connection.websocket.send_text(message.model_dump_json()),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"Send timeout for {connection.user_id}")
            # Don't await disconnect here to avoid deadlock
            asyncio.create_task(self._safe_disconnect(connection))
            raise
        except Exception as e:
            logger.warning(f"Send failed: {e}")
            asyncio.create_task(self._safe_disconnect(connection))
            raise
    
    async def _safe_disconnect(self, connection: Connection):
        """Safely disconnect a connection without blocking."""
        try:
            await self.disconnect(connection)
        except Exception as e:
            logger.warning(f"Error in safe disconnect: {e}")

    async def send_error(
        self,
        connection: Connection,
        error: str,
        request_id: str | None = None
    ):
        """Send error message."""
        await self.send_to_connection(
            connection,
            WSMessage(
                type=WSMessageType.ERROR,
                payload={"error": error},
                request_id=request_id,
            )
        )

    def is_online(self, user_id: str) -> bool:
        """Check if user has active connections."""
        return user_id in self._connections and len(self._connections[user_id]) > 0

    def get_online_users(self) -> list[str]:
        """Get list of online user IDs."""
        return list(self._connections.keys())

    def get_all_sessions(self) -> list[dict]:
        """Get list of all active sessions with details."""
        sessions = []
        for user_id, connections in self._connections.items():
            for conn in connections:
                sessions.append({
                    "user_id": user_id,
                    "device_id": conn.device_id,
                    "connected_at": conn.connected_at.isoformat(),
                    "last_ping": conn.last_ping.isoformat(),
                })
        return sessions

    def get_user_sessions(self, user_id: str) -> list[dict]:
        """Get all sessions for a specific user."""
        connections = self._connections.get(user_id, [])
        return [
            {
                "user_id": user_id,
                "device_id": conn.device_id,
                "connected_at": conn.connected_at.isoformat(),
                "last_ping": conn.last_ping.isoformat(),
            }
            for conn in connections
        ]

    async def disconnect_user(self, user_id: str, reason: str = "Disconnected by administrator") -> int:
        """
        Close all sessions for a specific user.
        Returns number of sessions closed.
        """
        connections = self._connections.get(user_id, [])
        if not connections:
            return 0
        
        count = len(connections)
        # Make a copy since disconnect() modifies the list
        for conn in list(connections):
            await self._close_connection(conn, reason, code=4001)
            await self.disconnect(conn)
        
        logger.info(f"Admin disconnected user {user_id}: {count} sessions closed")
        return count

    async def disconnect_session(self, user_id: str, device_id: str | None, reason: str = "Disconnected by administrator") -> bool:
        """
        Close a specific session by user_id and device_id.
        Returns True if session was found and closed.
        """
        connections = self._connections.get(user_id, [])
        for conn in connections:
            if conn.device_id == device_id:
                await self._close_connection(conn, reason, code=4001)
                await self.disconnect(conn)
                logger.info(f"Admin disconnected session: user={user_id}, device={device_id}")
                return True
        return False

    async def _broadcast_status(self, user_id: str, online: bool):
        """Broadcast user online/offline status to their contacts."""
        status = "online" if online else "offline"
        logger.info(f"User {user_id} is now {status}")
        
        # Notify all connected users about this user's status
        msg_type = WSMessageType.USER_ONLINE if online else WSMessageType.USER_OFFLINE
        message = WSMessage(
            type=msg_type,
            payload={"user_id": user_id}
        )
        
        # Get a copy of connections without lock to prevent deadlock
        connections_copy = dict(self._connections)
        
        # Send to all other connected users
        for other_user_id, connections in connections_copy.items():
            if other_user_id != user_id:
                for conn in list(connections):
                    try:
                        await asyncio.wait_for(
                            conn.websocket.send_text(message.model_dump_json()),
                            timeout=2.0
                        )
                    except Exception:
                        pass

    async def _close_connection(self, connection: Connection, reason: str = "", code: int = 1000):
        """Close a WebSocket connection."""
        try:
            await connection.websocket.close(code=code, reason=reason)
        except Exception:
            pass

    async def _heartbeat_loop(self):
        """Monitor connections and disconnect stale ones."""
        while True:
            try:
                await asyncio.sleep(settings.ws_heartbeat_interval)

                now = datetime.now(timezone.utc)
                timeout = settings.ws_heartbeat_interval * 3  # 3 missed pings

                stale: list[Connection] = []

                async with self._lock:
                    for connections in self._connections.values():
                        for conn in connections:
                            if (now - conn.last_ping).total_seconds() > timeout:
                                stale.append(conn)

                for conn in stale:
                    logger.warning(f"Closing stale connection for {conn.user_id}")
                    await self._close_connection(conn, "Heartbeat timeout")
                    await self.disconnect(conn)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Heartbeat error: {e}")

    async def _handle_call_signal(self, connection: Connection, msg: WSMessage):
        """Handle WebRTC call signaling."""
        payload = msg.payload or {}
        target_id = payload.get('target_id')
        if not target_id:
            await self.send_error(connection, "target_id required")
            return
        
        # Check call permission for CALL_OFFER
        if msg.type == WSMessageType.CALL_OFFER:
            from app.database import async_session_maker
            from app.models.user import User
            from sqlalchemy import select
            async with async_session_maker() as session:
                result = await session.execute(select(User).where(User.id == connection.user_id))
                user = result.scalar_one_or_none()
                if user and not user.can_call:
                    await self.send_error(connection, "You are not allowed to make calls")
                    return
        forward_payload = {**payload, 'caller_id': connection.user_id}
        forward_msg = WSMessage(
            type=msg.type,
            payload=forward_payload,
            request_id=msg.request_id
        )
        sent = await self.send_to_user(target_id, forward_msg)
        if not sent and msg.type == WSMessageType.CALL_OFFER:
            # User is offline - try to send push notification
            await self._send_call_push(target_id, connection.user_id)
            await self.send_to_connection(
                connection,
                WSMessage(
                    type=WSMessageType.CALL_END,
                    payload={'reason': 'offline', 'target_id': target_id}
                )
            )

    async def _handle_typing(self, connection: Connection, msg: WSMessage):
        """Handle typing indicator - forward to recipient(s)."""
        payload = msg.payload or {}
        recipient_id = payload.get('recipient_id')
        group_id = payload.get('group_id')
        
        # Get sender's display name
        sender_name = None
        try:
            from app.database import async_session_maker
            from app.models.user import User
            from sqlalchemy import select
            async with async_session_maker() as session:
                result = await session.execute(select(User).where(User.id == connection.user_id))
                user = result.scalar_one_or_none()
                if user:
                    sender_name = user.display_name or user.username
        except Exception as e:
            logger.warning(f"Failed to get sender name: {e}")
            sender_name = "Someone"
        
        typing_msg = WSMessage(
            type=WSMessageType.USER_TYPING,
            payload={
                'user_id': connection.user_id,
                'user_name': sender_name,
                'recipient_id': recipient_id,
                'group_id': group_id,
            }
        )
        
        if group_id:
            # Group chat - send to all group members except sender
            try:
                from app.database import async_session_maker
                from app.models.group import GroupMember
                from sqlalchemy import select
                async with async_session_maker() as session:
                    result = await session.execute(
                        select(GroupMember.user_id).where(GroupMember.group_id == group_id)
                    )
                    member_ids = [row[0] for row in result.fetchall()]
                    
                    for member_id in member_ids:
                        if member_id != connection.user_id:
                            await self.send_to_user(member_id, typing_msg)
            except Exception as e:
                logger.warning(f"Failed to send typing to group: {e}")
        elif recipient_id:
            # Direct message - send to recipient
            await self.send_to_user(recipient_id, typing_msg)

    async def _send_call_push(self, target_user_id: str, caller_user_id: str):
        """Send push notification for incoming call and cleanup invalid subscriptions."""
        try:
            from app.database import async_session_maker
            from app.models.user import User, PushSubscription
            from app.services.push_service import push_service
            from sqlalchemy import select, delete

            async with async_session_maker() as db:
                # Get caller name
                caller = await db.execute(
                    select(User).where(User.id == caller_user_id)
                )
                caller = caller.scalar_one_or_none()
                caller_name = caller.display_name or caller.username if caller else "Unknown"

                # Get target's push subscriptions
                result = await db.execute(
                    select(PushSubscription).where(PushSubscription.user_id == target_user_id)
                )
                subscriptions = result.scalars().all()

                subscriptions_to_remove = []

                for sub in subscriptions:
                    subscription_info = {
                        "endpoint": sub.endpoint,
                        "keys": {
                            "p256dh": sub.p256dh,
                            "auth": sub.auth
                        }
                    }
                    push_result = push_service.send_call_notification(subscription_info, caller_name, caller_user_id)
                    
                    if push_result.should_remove:
                        subscriptions_to_remove.append(sub.id)
                        logger.info(f"Marking subscription {sub.id} for removal (invalid)")
                    elif push_result.success:
                        logger.info(f"Push notification sent to {target_user_id}")

                # Remove invalid subscriptions from DB
                if subscriptions_to_remove:
                    await db.execute(
                        delete(PushSubscription).where(PushSubscription.id.in_(subscriptions_to_remove))
                    )
                    await db.commit()
                    logger.info(f"Removed {len(subscriptions_to_remove)} invalid push subscriptions")
        except Exception as e:
            logger.error(f"Failed to send push notification: {e}")


# Global instance
ws_manager = WebSocketManager()


async def websocket_endpoint(websocket: WebSocket, user_id: str, device_id: str | None, already_accepted: bool = False):
    """WebSocket endpoint handler."""
    connection = await ws_manager.connect(websocket, user_id, device_id, already_accepted=already_accepted)

    try:
        while True:
            data = await websocket.receive_text()
            await ws_manager.handle_message(connection, data)

    except WebSocketDisconnect:
        await ws_manager.disconnect(connection)
    except Exception as e:
        logger.exception(f"WebSocket error for {user_id}: {e}")
        await ws_manager.disconnect(connection)
