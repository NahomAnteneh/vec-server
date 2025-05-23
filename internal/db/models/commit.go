package models

import (
	"time"

	"gorm.io/gorm"
)

// Commit represents a version control commit in a repository
type Commit struct {
	ID             uint       `json:"id" gorm:"primarykey"`
	Hash           string     `json:"hash" gorm:"size:64;not null;uniqueIndex:idx_repo_hash"`
	RepositoryID   uint       `json:"repository_id" gorm:"not null;uniqueIndex:idx_repo_hash"`
	Repository     Repository `json:"repository" gorm:"foreignKey:RepositoryID"`
	AuthorName     string     `json:"author_name" gorm:"size:255;not null"`
	AuthorEmail    string     `json:"author_email" gorm:"size:255;not null"`
	CommitterName  string     `json:"committer_name" gorm:"size:255;not null"`
	CommitterEmail string     `json:"committer_email" gorm:"size:255;not null"`
	Message        string     `json:"message" gorm:"type:text;not null"`
	ParentHashes   string     `json:"parent_hashes" gorm:"type:text"` // Comma-separated list of parent commit hashes
	CommitDate     time.Time  `json:"commit_date" gorm:"not null"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TableName sets the table name for the Commit model
func (Commit) TableName() string {
	return "commits"
}

// CommitServiceImpl provides methods for interacting with commits in the database
type CommitServiceImpl struct {
	db *gorm.DB
}

// NewCommitService creates a new commit service
func NewCommitService(db *gorm.DB) CommitService {
	return &CommitServiceImpl{db: db}
}

// Create inserts a new commit into the database
func (s *CommitServiceImpl) Create(commit *Commit) error {
	return s.db.Create(commit).Error
}

// GetByHash retrieves a commit by its hash
func (s *CommitServiceImpl) GetByHash(repoID uint, hash string) (*Commit, error) {
	var commit Commit
	err := s.db.Where("repository_id = ? AND hash = ?", repoID, hash).
		First(&commit).Error
	return &commit, err
}

// ListByRepository retrieves commits for a repository with pagination
func (s *CommitServiceImpl) ListByRepository(repoID uint, limit, offset int) ([]*Commit, error) {
	var commits []*Commit
	err := s.db.Where("repository_id = ?", repoID).
		Order("commit_date DESC").
		Limit(limit).
		Offset(offset).
		Find(&commits).Error
	return commits, err
}

// GetCommitCount returns the total number of commits in a repository
func (s *CommitServiceImpl) GetCommitCount(repoID uint) (int64, error) {
	var count int64
	err := s.db.Model(&Commit{}).
		Where("repository_id = ?", repoID).
		Count(&count).Error
	return count, err
}
