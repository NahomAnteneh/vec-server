package models

import (
	"time"

	"gorm.io/gorm"
)

// Branch represents a version control branch in a repository
type Branch struct {
	ID           uint       `json:"id" gorm:"primarykey"`
	Name         string     `json:"name" gorm:"size:255;not null;uniqueIndex:idx_repo_name"`
	RepositoryID uint       `json:"repository_id" gorm:"not null;uniqueIndex:idx_repo_name"`
	Repository   Repository `json:"repository" gorm:"foreignKey:RepositoryID"`
	CommitHash   string     `json:"commit_hash" gorm:"size:64;not null"` // The commit hash the branch points to
	IsDefault    bool       `json:"is_default" gorm:"default:false"`     // Whether this is the default branch
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// TableName sets the table name for the Branch model
func (Branch) TableName() string {
	return "branches"
}

// BranchServiceImpl provides methods for interacting with branches in the database
type BranchServiceImpl struct {
	db *gorm.DB
}

// NewBranchService creates a new branch service
func NewBranchService(db *gorm.DB) BranchService {
	return &BranchServiceImpl{db: db}
}

// Create inserts a new branch into the database
func (s *BranchServiceImpl) Create(branch *Branch) error {
	return s.db.Create(branch).Error
}

// GetByName retrieves a branch by its name in a repository
func (s *BranchServiceImpl) GetByName(repoID uint, name string) (*Branch, error) {
	var branch Branch
	err := s.db.Where("repository_id = ? AND name = ?", repoID, name).
		First(&branch).Error
	return &branch, err
}

// GetDefaultBranch retrieves the default branch for a repository
func (s *BranchServiceImpl) GetDefaultBranch(repoID uint) (*Branch, error) {
	var branch Branch
	err := s.db.Where("repository_id = ? AND is_default = ?", repoID, true).
		First(&branch).Error
	return &branch, err
}

// ListByRepository retrieves branches for a repository
func (s *BranchServiceImpl) ListByRepository(repoID uint) ([]*Branch, error) {
	var branches []*Branch
	err := s.db.Where("repository_id = ?", repoID).
		Order("name").
		Find(&branches).Error
	return branches, err
}

// Update updates an existing branch in the database
func (s *BranchServiceImpl) Update(branch *Branch) error {
	return s.db.Save(branch).Error
}

// Delete removes a branch from the database
func (s *BranchServiceImpl) Delete(repoID uint, name string) error {
	return s.db.Where("repository_id = ? AND name = ?", repoID, name).
		Delete(&Branch{}).Error
}
