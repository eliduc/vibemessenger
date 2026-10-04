-- VibeMessenger v3.7.0 Database Migration
-- Run this script inside the postgres container:
-- docker exec -i vibemessenger-postgres psql -U vibemessenger -d vibemessenger < migration_v3.7.0.sql

-- Add signed prekey rotation fields to key_bundles
ALTER TABLE key_bundles 
ADD COLUMN IF NOT EXISTS signed_prekey_created_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE key_bundles 
ADD COLUMN IF NOT EXISTS previous_signed_prekey_id INTEGER;

ALTER TABLE key_bundles 
ADD COLUMN IF NOT EXISTS previous_signed_prekey VARCHAR(64);

ALTER TABLE key_bundles 
ADD COLUMN IF NOT EXISTS previous_signed_prekey_signature VARCHAR(128);

ALTER TABLE key_bundles 
ADD COLUMN IF NOT EXISTS previous_signed_prekey_created_at TIMESTAMPTZ;

-- Add session tracking fields to refresh_tokens
ALTER TABLE refresh_tokens 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

ALTER TABLE refresh_tokens 
ADD COLUMN IF NOT EXISTS user_agent VARCHAR(512);

ALTER TABLE refresh_tokens 
ADD COLUMN IF NOT EXISTS last_activity TIMESTAMPTZ DEFAULT NOW();

-- Update existing records
UPDATE key_bundles SET signed_prekey_created_at = NOW() WHERE signed_prekey_created_at IS NULL;
UPDATE refresh_tokens SET last_activity = created_at WHERE last_activity IS NULL;

-- Done
SELECT 'Migration v3.7.0 completed successfully' AS status;

-- User self-encryption key for encrypted notes/drafts
ALTER TABLE users ADD COLUMN IF NOT EXISTS self_encryption_key VARCHAR(128);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS encrypted_for_self TEXT;
