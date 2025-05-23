-- Create schema for repository metadata storage

-- +migrate Up
-- SQL in section 'Up' is executed when this migration is applied

-- Commits table
CREATE TABLE IF NOT EXISTS commits (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(64) NOT NULL,
    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    author_name VARCHAR(255) NOT NULL,
    author_email VARCHAR(255) NOT NULL,
    committer_name VARCHAR(255) NOT NULL,
    committer_email VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    parent_hashes TEXT,
    commit_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repository_id, hash)
);

-- Branches table
CREATE TABLE IF NOT EXISTS branches (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_hash VARCHAR(64) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repository_id, name)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_commits_repository_id ON commits(repository_id);
CREATE INDEX IF NOT EXISTS idx_commits_hash ON commits(hash);
CREATE INDEX IF NOT EXISTS idx_commits_commit_date ON commits(commit_date);
CREATE INDEX IF NOT EXISTS idx_branches_repository_id ON branches(repository_id);
CREATE INDEX IF NOT EXISTS idx_branches_commit_hash ON branches(commit_hash);

-- +migrate Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE IF EXISTS branches;
DROP TABLE IF EXISTS commits; 