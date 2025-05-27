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

// PermissionServiceImpl provides methods for interacting with permissions in the database
type PermissionServiceImpl struct {
	db *gorm.DB
}

// NewPermissionService creates a new permission service
func NewPermissionService(db *gorm.DB) PermissionService {
	return &PermissionServiceImpl{db: db}
}

// Create inserts a new permission into the database
func (s *PermissionServiceImpl) Create(perm *Permission) error {
	if !isValidAccessLevel(perm.AccessLevel) {
		return errors.New("invalid access level")
	}
	return s.db.Create(perm).Error
}

// GetByUserAndRepo retrieves a permission by user ID and repository ID
func (s *PermissionServiceImpl) GetByUserAndRepo(userID, repoID uint) (*Permission, error) {
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
func (s *PermissionServiceImpl) Update(perm *Permission) error {
	if !isValidAccessLevel(perm.AccessLevel) {
		return errors.New("invalid access level")
	}
	return s.db.Save(perm).Error
}

// DeleteByUserAndRepo removes a permission by user ID and repository ID
func (s *PermissionServiceImpl) DeleteByUserAndRepo(userID, repoID uint) error {
	return s.db.Where("user_id = ? AND repository_id = ?", userID, repoID).Delete(&Permission{}).Error
}

// ListByRepository retrieves all permissions for a repository
func (s *PermissionServiceImpl) ListByRepository(repoID uint) ([]*Permission, error) {
	var perms []*Permission
	err := s.db.Where("repository_id = ?", repoID).
		Preload("User").
		Find(&perms).Error
	return perms, err
}

// HasPermission checks if a user has at least the specified permission level on a repository
func (s *PermissionServiceImpl) HasPermission(userID, repoID uint, requiredLevel string) (bool, error) {
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

// isValidAccessLevel checks if an access level is valid
func isValidAccessLevel(level string) bool {
	return level == ReadPermission || level == WritePermission || level == AdminPermission
}

// hasAtLeastPermissionLevel checks if the given permission level meets or exceeds the required level
func hasAtLeastPermissionLevel(currentLevel, requiredLevel string) bool {
	if currentLevel == AdminPermission {
		return true
	}
	if currentLevel == WritePermission && (requiredLevel == WritePermission || requiredLevel == ReadPermission) {
		return true
	}
	return currentLevel == requiredLevel
}
