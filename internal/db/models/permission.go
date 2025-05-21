package models

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// Permission types
const (
	ReadPermission  = "read"
	WritePermission = "write"
	AdminPermission = "admin"
)

// Permission represents a user's permission level on a repository
type Permission struct {
	ID           uint       `json:"id" gorm:"primarykey"`
	UserID       uint       `json:"user_id" gorm:"not null"`
	User         User       `json:"user" gorm:"foreignKey:UserID"`
	RepositoryID uint       `json:"repository_id" gorm:"not null"`
	Repository   Repository `json:"repository" gorm:"foreignKey:RepositoryID"`
	AccessLevel  string     `json:"access_level" gorm:"size:20;not null"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// TableName sets the table name for the Permission model
func (Permission) TableName() string {
	return "permissions"
}

// PermissionService provides methods for interacting with permissions in the database
type PermissionService struct {
	db *gorm.DB
}

// NewPermissionService creates a new permission service with the given database connection
func NewPermissionService(db *gorm.DB) *PermissionService {
	return &PermissionService{db: db}
}

// Create inserts a new permission into the database
func (s *PermissionService) Create(perm *Permission) error {
	// Validate access level
	if !isValidAccessLevel(perm.AccessLevel) {
		return errors.New("invalid access level")
	}
	return s.db.Create(perm).Error
}

// GetByUserAndRepo retrieves a permission by user ID and repository ID
func (s *PermissionService) GetByUserAndRepo(userID, repoID uint) (*Permission, error) {
	var perm Permission
	err := s.db.Where("user_id = ? AND repository_id = ?", userID, repoID).
		Preload("User").
		Preload("Repository").
		First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("permission not found")
		}
		return nil, err
	}
	return &perm, nil
}

// Update updates an existing permission in the database
func (s *PermissionService) Update(perm *Permission) error {
	// Validate access level
	if !isValidAccessLevel(perm.AccessLevel) {
		return errors.New("invalid access level")
	}
	return s.db.Save(perm).Error
}

// Delete removes a permission from the database
func (s *PermissionService) Delete(id uint) error {
	return s.db.Delete(&Permission{}, id).Error
}

// DeleteByUserAndRepo removes a permission by user ID and repository ID
func (s *PermissionService) DeleteByUserAndRepo(userID, repoID uint) error {
	return s.db.Where("user_id = ? AND repository_id = ?", userID, repoID).Delete(&Permission{}).Error
}

// ListByRepository retrieves all permissions for a repository with pagination
func (s *PermissionService) ListByRepository(repoID uint) ([]*Permission, error) {
	var perms []*Permission
	err := s.db.Where("repository_id = ?", repoID).
		Preload("User").
		Find(&perms).Error
	return perms, err
}

// ListByUser retrieves all permissions for a user
func (s *PermissionService) ListByUser(userID uint) ([]*Permission, error) {
	var perms []*Permission
	err := s.db.Where("user_id = ?", userID).
		Preload("Repository").
		Preload("Repository.Owner").
		Find(&perms).Error
	return perms, err
}

// HasPermission checks if a user has at least the specified permission level on a repository
func (s *PermissionService) HasPermission(userID, repoID uint, requiredLevel string) (bool, error) {
	// Get the repository to check if the user is the owner (owners have implicit admin access)
	var repo Repository
	err := s.db.First(&repo, repoID).Error
	if err != nil {
		return false, err
	}

	// Repository owner has implicit admin permission
	if repo.OwnerID == userID {
		return true, nil
	}

	// For public repositories, everyone has read access
	if repo.IsPublic && requiredLevel == ReadPermission {
		return true, nil
	}

	// Check explicit permissions
	var perm Permission
	err = s.db.Where("user_id = ? AND repository_id = ?", userID, repoID).First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	return hasAtLeastPermissionLevel(perm.AccessLevel, requiredLevel), nil
}

// Helper functions

// isValidAccessLevel checks if an access level is valid
func isValidAccessLevel(level string) bool {
	return level == ReadPermission || level == WritePermission || level == AdminPermission
}

// hasAtLeastPermissionLevel checks if the given permission level is at least the required level
func hasAtLeastPermissionLevel(currentLevel, requiredLevel string) bool {
	// Admin has all permissions
	if currentLevel == AdminPermission {
		return true
	}

	// Write includes read permission
	if currentLevel == WritePermission && requiredLevel == ReadPermission {
		return true
	}

	// Exact match
	return currentLevel == requiredLevel
}
