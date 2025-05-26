-- Refactor object hashes and commit parent relationships

-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

-- Alter 'commits' table
-- 1. Rename 'hash' to 'commit_id' to match the new model field CommitID.
ALTER TABLE commits RENAME COLUMN hash TO commit_id;

-- 2. Add 'tree_hash' column.
ALTER TABLE commits ADD COLUMN tree_hash VARCHAR(64) NOT NULL DEFAULT 'temp_tree_hash_placeholder'; -- Add default for existing rows, then remove
-- Note: Existing rows will get a placeholder. This should be updated with actual data if possible,
-- or ensure new code handles this. For a clean slate, one might TRUNCATE commits if data migration is too complex.
-- For a production system, a more sophisticated data migration for tree_hash would be needed.

-- 3. Drop the old 'parent_hashes' TEXT column.
ALTER TABLE commits DROP COLUMN parent_hashes;

-- 4. Adjust timestamp columns to match model (AuthoredAt, CommittedAt)
-- Assuming old 'commit_date' corresponds to 'authored_at'.
ALTER TABLE commits RENAME COLUMN commit_date TO authored_at;
-- Add 'committed_at'. For existing records, it might be same as authored_at or CURRENT_TIMESTAMP.
ALTER TABLE commits ADD COLUMN committed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Remove default for tree_hash after existing rows are handled (or if this is for a new schema)
-- For a real migration, you might run an update script here before removing default.
ALTER TABLE commits ALTER COLUMN tree_hash DROP DEFAULT;
ALTER TABLE commits ALTER COLUMN committed_at DROP DEFAULT;


-- Create 'commit_parents' join table for many-to-many relationship between commits (parents/children)
CREATE TABLE IF NOT EXISTS commit_parents (
    child_commit_id VARCHAR(64) NOT NULL REFERENCES commits(commit_id) ON DELETE CASCADE,
    parent_commit_id VARCHAR(64) NOT NULL REFERENCES commits(commit_id) ON DELETE CASCADE,
    PRIMARY KEY (child_commit_id, parent_commit_id)
);

CREATE INDEX IF NOT EXISTS idx_commit_parents_child_id ON commit_parents(child_commit_id);
CREATE INDEX IF NOT EXISTS idx_commit_parents_parent_id ON commit_parents(parent_commit_id);


-- Alter 'branches' table
-- 1. Rename 'commit_hash' to 'commit_id' to match the new model field CommitID.
ALTER TABLE branches RENAME COLUMN commit_hash TO commit_id;


-- Update unique constraints and indexes if they referred to old column names
-- For 'commits' table, the unique constraint was on (repository_id, hash), now (repository_id, commit_id)
-- Most RDBMS handle this automatically with RENAME COLUMN if the index was on the column itself.
-- If it was a named constraint, it might need to be dropped and recreated.
-- Example for PostgreSQL if needed (syntax might vary):
-- ALTER TABLE commits DROP CONSTRAINT IF EXISTS commits_repository_id_hash_key; -- If such a named constraint exists
-- ALTER TABLE commits ADD CONSTRAINT commits_repository_id_commit_id_key UNIQUE (repository_id, commit_id);
-- Similar for indexes like idx_commits_hash -> idx_commits_commit_id
DROP INDEX IF EXISTS idx_commits_hash;
CREATE INDEX IF NOT EXISTS idx_commits_commit_id ON commits(commit_id);

-- For 'branches' table, index idx_branches_commit_hash -> idx_branches_commit_id
DROP INDEX IF EXISTS idx_branches_commit_hash;
CREATE INDEX IF NOT EXISTS idx_branches_commit_id ON branches(commit_id);


-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

-- Revert 'branches' table changes
ALTER TABLE branches RENAME COLUMN commit_id TO commit_hash;
DROP INDEX IF EXISTS idx_branches_commit_id;
CREATE INDEX IF NOT EXISTS idx_branches_commit_hash ON branches(commit_hash);

-- Drop 'commit_parents' table
DROP TABLE IF EXISTS commit_parents;

-- Revert 'commits' table changes
ALTER TABLE commits RENAME COLUMN commit_id TO hash;
ALTER TABLE commits DROP COLUMN tree_hash;
ALTER TABLE commits ADD COLUMN parent_hashes TEXT;
ALTER TABLE commits RENAME COLUMN authored_at TO commit_date;
ALTER TABLE commits DROP COLUMN committed_at;

DROP INDEX IF EXISTS idx_commits_commit_id;
CREATE INDEX IF NOT EXISTS idx_commits_hash ON commits(hash);

-- Note: Reverting the unique constraint on commits might need specific DDL if it was renamed/recreated.
-- If it was handled automatically by column rename, this might be okay. 