package models

import (
	"gorm.io/gorm"
)

// Branch represents a branch in a repository.
// It points to a specific commit via CommitID (SHA-256 hex string).
type Branch struct {
	gorm.Model
	Name         string `gorm:"type:varchar(255);uniqueIndex:idx_repo_branch_name;not null"`
	RepositoryID uint   `gorm:"uniqueIndex:idx_repo_branch_name;not null"` // Foreign key to Repository
	CommitID     string `gorm:"type:varchar(64);not null"`                 // SHA-256 hash of the commit this branch points to
	IsDefault    bool   `gorm:"default:false"`

	// Relationships
	Repository Repository `gorm:"foreignKey:RepositoryID"`
	// The Commit struct this branch points to. Ensure foreignKey and references match Commit model keys.
	Commit Commit `gorm:"foreignKey:CommitID;references:CommitID"`
}

// branchGorm implements BranchService using GORM.
// The BranchService interface is defined in interfaces.go
type branchGorm struct {
	db *gorm.DB
}

// NewBranchService creates a new BranchService.
func NewBranchService(db *gorm.DB) BranchService { // Returns the interface type
	return &branchGorm{db}
}

// Create creates a new branch.
func (bg *branchGorm) Create(branch *Branch) error {
	return bg.db.Create(branch).Error
}

// GetByName retrieves a branch by its name and repository ID.
func (bg *branchGorm) GetByName(repoID uint, name string) (*Branch, error) {
	var branch Branch
	err := bg.db.Preload("Commit").Where("repository_id = ? AND name = ?", repoID, name).First(&branch).Error
	if err != nil {
		return nil, err
	}
	return &branch, nil
}

// GetDefaultBranch retrieves the default branch for a repository.
func (bg *branchGorm) GetDefaultBranch(repoID uint) (*Branch, error) {
	var branch Branch
	err := bg.db.Preload("Commit").Where("repository_id = ? AND is_default = ?", repoID, true).First(&branch).Error
	if err != nil {
		// It's possible no default branch is set, or multiple are (which is a data integrity issue)
		return nil, err
	}
	return &branch, nil
}

// ListByRepository retrieves all branches for a repository.
func (bg *branchGorm) ListByRepository(repoID uint) ([]*Branch, error) {
	var branches []*Branch
	err := bg.db.Preload("Commit").Where("repository_id = ?", repoID).Find(&branches).Error
	return branches, err
}

// Update updates a branch (e.g., to change its commit ID or default status).
func (bg *branchGorm) Update(branch *Branch) error {
	// Ensure you are only updating specific fields or use Model(&Branch{}).Where(...).Updates(...)
	// to avoid accidentally blanking fields if `branch` is not fully populated.
	// GORM's `Save` method will update all fields, or insert if primary key is zero.
	return bg.db.Save(branch).Error
}

// Delete deletes a branch.
func (bg *branchGorm) Delete(repoID uint, name string) error {
	return bg.db.Where("repository_id = ? AND name = ?", repoID, name).Delete(&Branch{}).Error
}
