package models

import (
	"time"

	"gorm.io/gorm"
)

// Commit represents a commit in a repository.
// Hashes are stored as 64-character hex strings (SHA-256 from core package).
type Commit struct {
	gorm.Model
	RepositoryID   uint   `gorm:"index;not null"`                        // Foreign key to Repository
	CommitID       string `gorm:"type:varchar(64);uniqueIndex;not null"` // SHA-256 hash of the commit
	TreeHash       string `gorm:"type:varchar(64);not null"`             // SHA-256 hash of the tree
	AuthorName     string
	AuthorEmail    string
	AuthoredAt     time.Time
	CommitterName  string
	CommitterEmail string
	CommittedAt    time.Time
	Message        string `gorm:"type:text"`

	// Relationships
	// Parents are handled through a join table CommitParents
	Parents  []*Commit `gorm:"many2many:commit_parents;foreignKey:CommitID;joinForeignKey:ChildCommitID;References:CommitID;joinReferences:ParentCommitID"` // Parent commits
	Children []*Commit `gorm:"many2many:commit_parents;foreignKey:CommitID;joinForeignKey:ParentCommitID;References:CommitID;joinReferences:ChildCommitID"` // Child commits
	Branches []*Branch `gorm:"foreignKey:CommitID;references:CommitID"`                                                                                     // Branches that point to this commit
}

// commitGorm implements CommitService using GORM.
// The CommitService interface is defined in interfaces.go
type commitGorm struct {
	db *gorm.DB
}

// NewCommitService creates a new CommitService.
func NewCommitService(db *gorm.DB) CommitService { // Returns the interface type
	return &commitGorm{db}
}

// CreateCommit creates a new commit record.
func (cg *commitGorm) CreateCommit(commit *Commit) error {
	return cg.db.Create(commit).Error
}

// GetCommitByHash retrieves a commit by its hash and repository ID.
func (cg *commitGorm) GetCommitByHash(repoID uint, commitID string) (*Commit, error) {
	var commit Commit
	err := cg.db.Where("repository_id = ? AND commit_id = ?", repoID, commitID).First(&commit).Error
	if err != nil {
		return nil, err
	}
	return &commit, nil
}

// GetCommitsByRepoID retrieves all commits for a given repository ID.
func (cg *commitGorm) GetCommitsByRepoID(repoID uint) ([]*Commit, error) {
	var commits []*Commit // Changed to []*Commit
	err := cg.db.Where("repository_id = ?", repoID).Find(&commits).Error
	return commits, err
}

// AddCommitParent links a commit to a parent commit.
// This needs careful handling of the join table.
func (cg *commitGorm) AddCommitParent(commit *Commit, parent *Commit) error {
	// Simpler: If GORM handles the association correctly via struct fields:
	return cg.db.Model(commit).Association("Parents").Append(parent)
}

// GetCommitParents retrieves the parent commits of a given commit.
func (cg *commitGorm) GetCommitParents(commitID string) ([]*Commit, error) { // Return type changed to []*Commit
	var commit Commit
	// First, fetch the commit to ensure it exists and to use its ID for the association.
	// Assuming CommitID is the primary key for association purposes here.
	err := cg.db.Preload("Parents").First(&commit, "commit_id = ?", commitID).Error
	if err != nil {
		return nil, err
	}
	return commit.Parents, nil
}

// GetCommitChildren retrieves the children commits of a given commit.
func (cg *commitGorm) GetCommitChildren(commitID string) ([]*Commit, error) { // Return type changed to []*Commit
	var commit Commit
	err := cg.db.Preload("Children").First(&commit, "commit_id = ?", commitID).Error
	if err != nil {
		return nil, err
	}
	return commit.Children, nil
}

// You might need a specific join table model if GORM's default many2many
// handling is problematic with string-based unique keys rather than uint IDs.
// type CommitParentRel struct {
// ChildCommitID  string `gorm:"primaryKey"` // Or use commit.ID (uint) if available and preferred for join
// ParentCommitID string `gorm:"primaryKey"` // Or use commit.ID (uint)
// Child          Commit `gorm:"foreignKey:ChildCommitID;references:CommitID"`
// Parent         Commit `gorm:"foreignKey:ParentCommitID;references:CommitID"`
// }
// func (cg *commitGorm) AddCommitParent(commit *Commit, parent *Commit) error {
// 	 relation := CommitParentRel{ChildCommitID: commit.CommitID, ParentCommitID: parent.CommitID}
// 	 return cg.db.Create(&relation).Error
// }
