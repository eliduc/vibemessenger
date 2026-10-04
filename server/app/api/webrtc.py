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
WebRTC Configuration API
Provides ICE server configuration for WebRTC calls
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from ..config import settings
from .auth import get_current_user_id

router = APIRouter(prefix="/webrtc", tags=["webrtc"])


class IceServer(BaseModel):
    urls: str | list[str]
    username: str | None = None
    credential: str | None = None


class IceServersResponse(BaseModel):
    ice_servers: list[IceServer]
    enabled: bool


@router.get("/ice-servers", response_model=IceServersResponse)
async def get_ice_servers(user_id: str = Depends(get_current_user_id)):
    if not settings.turn_enabled:
        return IceServersResponse(ice_servers=[], enabled=False)
    
    ice_servers = []
    
    if settings.stun_server_url:
        ice_servers.append(IceServer(urls=settings.stun_server_url))
    
    if settings.turn_username and settings.turn_credential:
        base_url = settings.turn_server_url
        port = settings.turn_server_port
        
        ice_servers.append(IceServer(
            urls=f"turn:{base_url}:80",
            username=settings.turn_username,
            credential=settings.turn_credential
        ))
        ice_servers.append(IceServer(
            urls=f"turn:{base_url}:80?transport=tcp",
            username=settings.turn_username,
            credential=settings.turn_credential
        ))
        ice_servers.append(IceServer(
            urls=f"turn:{base_url}:{port}",
            username=settings.turn_username,
            credential=settings.turn_credential
        ))
        ice_servers.append(IceServer(
            urls=f"turns:{base_url}:{port}?transport=tcp",
            username=settings.turn_username,
            credential=settings.turn_credential
        ))
    
    return IceServersResponse(ice_servers=ice_servers, enabled=True)

