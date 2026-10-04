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
