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
API Tests for Secure Messenger Server
"""
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.main import app
from app.database import Base, get_db
from app.config import settings


# Test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client(setup_database):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def auth_client(client):
    """Client with authenticated user."""
    # Register user
    response = await client.post("/api/v1/auth/register", json={
        "username": "testuser",
        "password": "TestPass123",
        "display_name": "Test User",
    })
    
    if response.status_code == 409:
        # User exists, login instead
        response = await client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "TestPass123",
        })
    
    tokens = response.json()["tokens"]
    client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
    client.refresh_token = tokens["refresh_token"]
    client.user_id = response.json()["user"]["id"]
    
    yield client


# ============== Health Tests ==============

class TestHealth:
    async def test_root(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
    
    async def test_health(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


# ============== Auth Tests ==============

class TestAuth:
    async def test_register_success(self, client):
        response = await client.post("/api/v1/auth/register", json={
            "username": "newuser",
            "password": "SecurePass123",
            "display_name": "New User",
        })
        
        # May be 201 (new) or 409 (exists from previous test)
        if response.status_code == 201:
            data = response.json()
            assert "user" in data
            assert "tokens" in data
            assert data["user"]["username"] == "newuser"
            assert "access_token" in data["tokens"]
    
    async def test_register_weak_password(self, client):
        response = await client.post("/api/v1/auth/register", json={
            "username": "weakuser",
            "password": "weak",
        })
        assert response.status_code == 422
    
    async def test_register_invalid_username(self, client):
        response = await client.post("/api/v1/auth/register", json={
            "username": "invalid user!",
            "password": "SecurePass123",
        })
        assert response.status_code == 422
    
    async def test_login_success(self, client):
        # First register
        await client.post("/api/v1/auth/register", json={
            "username": "logintest",
            "password": "SecurePass123",
        })
        
        # Then login
        response = await client.post("/api/v1/auth/login", json={
            "username": "logintest",
            "password": "SecurePass123",
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "tokens" in data
    
    async def test_login_wrong_password(self, client):
        response = await client.post("/api/v1/auth/login", json={
            "username": "logintest",
            "password": "WrongPass123",
        })
        assert response.status_code == 401
    
    async def test_login_nonexistent_user(self, client):
        response = await client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "SomePass123",
        })
        assert response.status_code == 401
    
    async def test_get_me(self, auth_client):
        response = await auth_client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
    
    async def test_get_me_unauthorized(self, client):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 403  # No auth header
    
    async def test_refresh_token(self, auth_client):
        response = await auth_client.post("/api/v1/auth/refresh", json={
            "refresh_token": auth_client.refresh_token,
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data


# ============== Keys Tests ==============

class TestKeys:
    async def test_upload_bundle(self, auth_client):
        response = await auth_client.post("/api/v1/keys/bundle", json={
            "identity_key": "dGVzdGlkZW50aXR5a2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
            "signed_prekey_id": 1,
            "signed_prekey": "dGVzdHNpZ25lZHByZWtleTEyMzQ1Njc4OTAxMjM0NTY3OA==",
            "signed_prekey_signature": "dGVzdHNpZ25hdHVyZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
            "one_time_prekeys": [
                {"id": 1, "key": "b3RwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw"},
                {"id": 2, "key": "b3RwMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx"},
            ],
        })
        
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "ok"
        assert data["prekeys_count"] == 2
    
    async def test_get_bundle_status(self, auth_client):
        response = await auth_client.get("/api/v1/keys/bundle/status/me")
        assert response.status_code == 200
        data = response.json()
        assert "has_bundle" in data
    
    async def test_add_prekeys(self, auth_client):
        # First upload bundle
        await auth_client.post("/api/v1/keys/bundle", json={
            "identity_key": "dGVzdGlkZW50aXR5a2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
            "signed_prekey_id": 1,
            "signed_prekey": "dGVzdHNpZ25lZHByZWtleTEyMzQ1Njc4OTAxMjM0NTY3OA==",
            "signed_prekey_signature": "dGVzdHNpZ25hdHVyZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
            "one_time_prekeys": [],
        })
        
        # Add prekeys
        response = await auth_client.post("/api/v1/keys/bundle/prekeys", json=[
            {"id": 10, "key": "bmV3b3RwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY="},
            {"id": 11, "key": "bmV3b3RwMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc="},
        ])
        
        assert response.status_code == 200


# ============== Messages Tests ==============

class TestMessages:
    async def test_send_message_to_nonexistent_user(self, auth_client):
        response = await auth_client.post("/api/v1/messages/send", json={
            "recipient_id": "nonexistent-uuid",
            "encrypted_payload": "dGVzdG1lc3NhZ2U=",
        })
        assert response.status_code == 404
    
    async def test_get_pending_messages(self, auth_client):
        response = await auth_client.get("/api/v1/messages/pending")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    async def test_ack_messages(self, auth_client):
        response = await auth_client.post("/api/v1/messages/ack", json={
            "message_ids": [],
            "status": "delivered",
        })
        assert response.status_code == 204


# ============== WebSocket Tests ==============

class TestWebSocket:
    async def test_ws_without_token(self, client):
        # WebSocket without token should fail
        # Note: This is a simplified test, real WS testing requires different approach
        response = await client.get("/ws")
        # Will get 400 because no token query param
        assert response.status_code in [400, 422]


# ============== Integration Tests ==============

class TestIntegration:
    async def test_full_registration_flow(self, client):
        """Test complete registration flow with key upload."""
        # 1. Register
        response = await client.post("/api/v1/auth/register", json={
            "username": "fullflowuser",
            "password": "SecurePass123",
        })
        
        if response.status_code == 409:
            # Already exists, login
            response = await client.post("/api/v1/auth/login", json={
                "username": "fullflowuser",
                "password": "SecurePass123",
            })
        
        assert response.status_code in [200, 201]
        tokens = response.json()["tokens"]
        
        # 2. Set auth header
        client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
        
        # 3. Upload keys
        response = await client.post("/api/v1/keys/bundle", json={
            "identity_key": "dGVzdGlkZW50aXR5a2V5MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
            "signed_prekey_id": 1,
            "signed_prekey": "dGVzdHNpZ25lZHByZWtleTEyMzQ1Njc4OTAxMjM0NTY3OA==",
            "signed_prekey_signature": "dGVzdHNpZ25hdHVyZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
            "one_time_prekeys": [
                {"id": i, "key": f"b3RwezB9MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw"} 
                for i in range(1, 11)
            ],
        })
        
        assert response.status_code == 201
        
        # 4. Check status
        response = await client.get("/api/v1/keys/bundle/status/me")
        assert response.status_code == 200
        data = response.json()
        assert data["has_bundle"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
