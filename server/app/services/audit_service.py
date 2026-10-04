"""
Audit Service for security event logging.

Provides centralized audit logging for:
- Authentication events (login, logout, password changes)
- User management (registration, blocking, admin actions)
- Security events (rate limiting, suspicious activity)
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import Request

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from app.models.audit import (
    AuditLog, AuditEventType, AuditSeverity,
    AuditLogCreate, AuditLogResponse, AuditLogQuery
)


logger = logging.getLogger(__name__)


class AuditService:
    """
    Centralized audit logging service.
    
    Usage:
        await audit_service.log_event(
            db=db,
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user.id,
            username=user.username,
            request=request,
            details={"device": "mobile"}
        )
    """
    
    @staticmethod
    def get_client_ip(request: Optional[Request]) -> Optional[str]:
        """Extract client IP from request, handling proxies."""
        if not request:
            return None
        
        # Check X-Forwarded-For header (set by nginx/load balancer)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP (original client)
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct client
        if request.client:
            return request.client.host
        
        return None
    
    @staticmethod
    def get_user_agent(request: Optional[Request]) -> Optional[str]:
        """Extract user agent from request."""
        if not request:
            return None
        return request.headers.get("User-Agent", "")[:500]  # Limit length
    
    async def log_event(
        self,
        db: AsyncSession,
        event_type: AuditEventType,
        severity: AuditSeverity = AuditSeverity.INFO,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        target_user_id: Optional[str] = None,
        target_resource_id: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        request: Optional[Request] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditLog:
        """
        Create an audit log entry.
        
        Args:
            db: Database session
            event_type: Type of event (from AuditEventType enum)
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            user_id: ID of user performing the action
            username: Username (cached for historical reference)
            target_user_id: ID of user being acted upon (if applicable)
            target_resource_id: ID of resource being acted upon
            target_resource_type: Type of resource ('user', 'group', etc.)
            request: FastAPI request object (for IP/user-agent extraction)
            ip_address: Override IP address (if request not available)
            details: Additional event-specific data (will be JSON serialized)
        
        Returns:
            Created AuditLog entry
        """
        # Extract request info
        client_ip = ip_address or self.get_client_ip(request)
        user_agent = self.get_user_agent(request)
        
        # Serialize details to JSON
        details_json = json.dumps(details) if details else None
        
        # Create audit log entry
        audit_log = AuditLog(
            event_type=event_type.value,
            severity=severity.value,
            user_id=user_id,
            username=username,
            target_user_id=target_user_id,
            target_resource_id=target_resource_id,
            target_resource_type=target_resource_type,
            ip_address=client_ip,
            user_agent=user_agent,
            details=details_json,
        )
        
        db.add(audit_log)
        await db.flush()  # Get ID without committing
        
        # Log to application logger as well
        log_message = (
            f"AUDIT: {event_type.value} | "
            f"user={user_id or 'anonymous'} | "
            f"ip={client_ip or 'unknown'} | "
            f"severity={severity.value}"
        )
        if target_user_id:
            log_message += f" | target_user={target_user_id}"
        if details:
            log_message += f" | details={details}"
        
        if severity == AuditSeverity.CRITICAL:
            logger.critical(log_message)
        elif severity == AuditSeverity.ERROR:
            logger.error(log_message)
        elif severity == AuditSeverity.WARNING:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        return audit_log
    
    async def log_login_success(
        self,
        db: AsyncSession,
        user_id: str,
        username: str,
        request: Optional[Request] = None,
        details: Optional[dict] = None,
    ) -> AuditLog:
        """Log successful login."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.LOGIN_SUCCESS,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            request=request,
            details=details,
        )
    
    async def log_login_failed(
        self,
        db: AsyncSession,
        username: str,
        request: Optional[Request] = None,
        reason: str = "invalid_credentials",
    ) -> AuditLog:
        """Log failed login attempt."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            severity=AuditSeverity.WARNING,
            username=username,
            request=request,
            details={"reason": reason},
        )
    
    async def log_password_change(
        self,
        db: AsyncSession,
        user_id: str,
        username: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log password change."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.PASSWORD_CHANGE,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            request=request,
        )
    
    async def log_totp_enabled(
        self,
        db: AsyncSession,
        user_id: str,
        username: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log 2FA enabled."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.TOTP_ENABLED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            request=request,
        )
    
    async def log_totp_disabled(
        self,
        db: AsyncSession,
        user_id: str,
        username: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log 2FA disabled."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.TOTP_DISABLED,
            severity=AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            request=request,
        )
    
    async def log_user_blocked(
        self,
        db: AsyncSession,
        blocker_id: str,
        blocker_username: str,
        blocked_id: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log user blocked another user."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.USER_BLOCKED,
            severity=AuditSeverity.INFO,
            user_id=blocker_id,
            username=blocker_username,
            target_user_id=blocked_id,
            target_resource_type="user",
            request=request,
        )
    
    async def log_user_unblocked(
        self,
        db: AsyncSession,
        blocker_id: str,
        blocker_username: str,
        blocked_id: str,
        request: Optional[Request] = None,
    ) -> AuditLog:
        """Log user unblocked another user."""
        return await self.log_event(
            db=db,
            event_type=AuditEventType.USER_UNBLOCKED,
            severity=AuditSeverity.INFO,
            user_id=blocker_id,
            username=blocker_username,
            target_user_id=blocked_id,
            target_resource_type="user",
            request=request,
        )
    
    async def log_admin_action(
        self,
        db: AsyncSession,
        admin_id: str,
        admin_username: str,
        action: str,
        target_user_id: Optional[str] = None,
        target_resource_id: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        request: Optional[Request] = None,
        details: Optional[dict] = None,
    ) -> AuditLog:
        """Log administrative action."""
        event_details = {"action": action}
        if details:
            event_details.update(details)
        
        return await self.log_event(
            db=db,
            event_type=AuditEventType.ADMIN_ACTION,
            severity=AuditSeverity.WARNING,
            user_id=admin_id,
            username=admin_username,
            target_user_id=target_user_id,
            target_resource_id=target_resource_id,
            target_resource_type=target_resource_type,
            request=request,
            details=event_details,
        )
    
    async def query_logs(
        self,
        db: AsyncSession,
        query: AuditLogQuery,
    ) -> list[AuditLog]:
        """
        Query audit logs with filters.
        
        Args:
            db: Database session
            query: Query parameters
            
        Returns:
            List of matching audit log entries
        """
        stmt = select(AuditLog)
        
        conditions = []
        
        if query.event_type:
            conditions.append(AuditLog.event_type == query.event_type.value)
        
        if query.user_id:
            conditions.append(AuditLog.user_id == query.user_id)
        
        if query.target_user_id:
            conditions.append(AuditLog.target_user_id == query.target_user_id)
        
        if query.ip_address:
            conditions.append(AuditLog.ip_address == query.ip_address)
        
        if query.severity:
            conditions.append(AuditLog.severity == query.severity.value)
        
        if query.start_date:
            conditions.append(AuditLog.created_at >= query.start_date)
        
        if query.end_date:
            conditions.append(AuditLog.created_at <= query.end_date)
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        stmt = stmt.order_by(desc(AuditLog.created_at))
        stmt = stmt.limit(query.limit).offset(query.offset)
        
        result = await db.execute(stmt)
        return result.scalars().all()


# Singleton instance
audit_service = AuditService()
