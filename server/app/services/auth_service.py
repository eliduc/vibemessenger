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
Authentication service with JWT and Argon2.
Version: 3.7.2 - Added access_token_jti for reliable session identification
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import hashlib
import secrets

from jose import jwt, JWTError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from fastapi import HTTPException, status, Request

from app.config import settings
from app.models.user import User, RefreshToken, UserCreate, TokenPair


ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def get_client_ip(request: Request | None) -> str | None:
    """Extract client IP from request, handling proxies."""
    if not request:
        return None
    
    # Check X-Forwarded-For header (from nginx/proxy)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return None


def get_user_agent(request: Request | None) -> str | None:
    """Extract and truncate user agent from request."""
    if not request:
        return None
    
    user_agent = request.headers.get("user-agent")
    if user_agent and len(user_agent) > 512:
        user_agent = user_agent[:509] + "..."
    
    return user_agent


class AuthService:
    
    @staticmethod
    def hash_password(password: str) -> str:
        return ph.hash(password)
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            ph.verify(password_hash, password)
            return True
        except VerifyMismatchError:
            return False
    
    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def create_access_token(user_id: str, device_id: str | None = None) -> tuple[str, datetime, str]:
        """
        Create access token with JWT ID.
        
        v3.7.2: Now returns (token, expires, jti) for session linking.
        
        Returns:
            tuple: (access_token, expires_at, jti)
        """
        expires = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
        jti = str(uuid4())
        
        payload = {
            "sub": user_id,
            "type": "access",
            "device_id": device_id,
            "exp": expires,
            "iat": datetime.now(timezone.utc),
            "jti": jti,
        }
        
        token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
        return token, expires, jti
    
    @staticmethod
    def create_refresh_token() -> str:
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def decode_access_token(token: str) -> dict:
        try:
            payload = jwt.decode(
                token, 
                settings.secret_key, 
                algorithms=[settings.jwt_algorithm]
            )
            
            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            return payload
            
        except JWTError:
            # КАО#070 (sec): do not leak python-jose internals to the client
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    async def register_user(
        self, 
        db: AsyncSession, 
        user_data: UserCreate,
        request: Request | None = None,
    ) -> tuple[User, TokenPair]:
        
        result = await db.execute(
            select(User).where(User.username == user_data.username)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )

        # Check display_name uniqueness
        result = await db.execute(
            select(User).where(User.display_name == user_data.display_name)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Display name already taken"
            )

        user = User(
            username=user_data.username,
            display_name=user_data.display_name or user_data.username,
            password_hash=self.hash_password(user_data.password),
            device_id=user_data.device_id,
        )
        
        db.add(user)
        await db.flush()
        
        tokens = await self._create_token_pair(db, user, user_data.device_id, request)
        
        return user, tokens
    
    async def login_user(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        device_id: str | None = None,
        request: Request | None = None,
        skip_totp: bool = False,
        create_tokens: bool = True,
    ) -> tuple[User, "TokenPair | None"]:

        result = await db.execute(
            select(User).where(User.username == username.lower())
        )
        user = result.scalar_one_or_none()

        if not user or not self.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )

        if user.is_blocked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is blocked. Please contact administrator."
            )

        user.last_seen = datetime.now(timezone.utc)
        if device_id:
            user.device_id = device_id

        # КАО#248 (#18): when the caller still has to clear a second factor (TOTP), do NOT mint a
        # session yet — otherwise a usable refresh token is committed even when 2FA fails. The caller
        # issues tokens via issue_tokens() only after the second factor passes.
        tokens = await self._create_token_pair(db, user, device_id, request) if create_tokens else None

        return user, tokens

    async def issue_tokens(
        self,
        db: AsyncSession,
        user: User,
        device_id: str | None = None,
        request: Request | None = None,
    ) -> TokenPair:
        """КАО#248 (#18): public token issuance, called after all auth factors (password + TOTP) pass."""
        return await self._create_token_pair(db, user, device_id, request)
    
    async def refresh_tokens(
        self,
        db: AsyncSession,
        refresh_token: str,
        request: Request | None = None,
    ) -> TokenPair:
        
        token_hash = self.hash_token(refresh_token)
        
        result = await db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.is_revoked == False,
                    RefreshToken.expires_at > datetime.now(timezone.utc),
                )
            )
        )
        db_token = result.scalar_one_or_none()
        
        if not db_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        result = await db.execute(
            select(User).where(User.id == db_token.user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active or user.is_blocked:  # КАО#009 (SER#23): block stops refresh
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or disabled"
            )
        
        # Revoke old token
        db_token.is_revoked = True
        
        # Create new token pair with updated tracking info
        tokens = await self._create_token_pair(db, user, db_token.device_id, request)
        
        return tokens
    
    async def logout(
        self,
        db: AsyncSession,
        user_id: str,
        refresh_token: str | None = None,
        all_devices: bool = False,
    ):
        if all_devices:
            result = await db.execute(
                select(RefreshToken).where(
                    and_(
                        RefreshToken.user_id == user_id,
                        RefreshToken.is_revoked == False,
                    )
                )
            )
            tokens = result.scalars().all()
            for token in tokens:
                token.is_revoked = True
        
        elif refresh_token:
            token_hash = self.hash_token(refresh_token)
            result = await db.execute(
                select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            )
            db_token = result.scalar_one_or_none()
            if db_token:
                db_token.is_revoked = True
    
    async def _create_token_pair(
        self,
        db: AsyncSession,
        user: User,
        device_id: str | None,
        request: Request | None = None,
    ) -> TokenPair:
        """
        Create access + refresh token pair.
        
        v3.7.2: Now stores access_token_jti in RefreshToken for reliable session identification.
        """
        access_token, expires, jti = self.create_access_token(user.id, device_id)
        refresh_token = self.create_refresh_token()
        
        # v3.7.0: Add session tracking info
        # v3.7.2: Add access_token_jti for session identification
        db_refresh = RefreshToken(
            user_id=user.id,
            token_hash=self.hash_token(refresh_token),
            device_id=device_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days),
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            last_activity=datetime.now(timezone.utc),
            access_token_jti=jti,  # v3.7.2: Link to access token
        )
        db.add(db_refresh)
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_expire_minutes * 60,
        )
    
    async def get_user_by_id(self, db: AsyncSession, user_id: str) -> User | None:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()


auth_service = AuthService()
