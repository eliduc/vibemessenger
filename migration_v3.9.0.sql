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
