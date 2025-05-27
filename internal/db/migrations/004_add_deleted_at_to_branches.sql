-- Add deleted_at for soft delete support to branches

-- +migrate Up
ALTER TABLE branches ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_branches_deleted_at ON branches(deleted_at);

-- +migrate Down
DROP INDEX IF EXISTS idx_branches_deleted_at;
ALTER TABLE branches DROP COLUMN deleted_at; 