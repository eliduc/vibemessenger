-- VibeMessenger - self-hosted end-to-end encrypted messenger.
-- Copyright (C) 2026 eliduc
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

-- Migration for VibeMessenger v3.9.0
-- Adds support for public groups, invite links, and role management

-- Add new columns to groups table
ALTER TABLE groups ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS invite_code VARCHAR(16) UNIQUE;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS invite_link_enabled BOOLEAN DEFAULT FALSE;

-- Create index for invite_code lookups
CREATE INDEX IF NOT EXISTS idx_groups_invite_code ON groups(invite_code) WHERE invite_code IS NOT NULL;

-- Verify the changes
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'groups' 
AND column_name IN ('is_public', 'invite_code', 'invite_link_enabled');
