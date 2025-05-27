-- Add deleted_at for soft delete support to commits table

-- +migrate Up
ALTER TABLE commits ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_commits_deleted_at ON commits(deleted_at);

-- +migrate Down
DROP INDEX IF EXISTS idx_commits_deleted_at;
ALTER TABLE commits DROP COLUMN deleted_at; 