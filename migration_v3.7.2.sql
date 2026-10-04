-- VibeMessenger - self-hosted end-to-end encrypted messenger.
-- Copyright (C) 2026 RLG
--
-- This program is free software: you may redistribute it and/or modify it under
-- the terms of the GNU Affero General Public License, version 3, as published by
-- the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY; without
-- even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
-- PURPOSE. See the GNU AGPL v3 <https://www.gnu.org/licenses/agpl-3.0.html>;
-- a verbatim copy ships in the LICENSE file at the root of this repository.
--
-- AGPL section 13: if you modify this program and let users interact with it
-- over a network, you must offer those users the complete corresponding source
-- of your modified version, at no charge, from a network server.

-- Migration v3.7.2: Add access_token_jti for reliable session identification
-- Run this migration on your PostgreSQL database

-- Add access_token_jti column to refresh_tokens table
ALTER TABLE refresh_tokens 
ADD COLUMN IF NOT EXISTS access_token_jti VARCHAR(36);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_access_token_jti 
ON refresh_tokens(access_token_jti);

-- Verify the column was added
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'refresh_tokens' 
AND column_name = 'access_token_jti';
