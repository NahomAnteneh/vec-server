package models

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// Repository represents a version control repository
type Repository struct {
	ID        uint      `json:"id" gorm:"primarykey"`
	Name      string    `json:"name" gorm:"size:255;not null"`
	OwnerID   uint      `json:"owner_id" gorm:"not null"`
	Owner     User      `json:"owner" gorm:"foreignKey:OwnerID"`
	IsPublic  bool      `json:"is_public" gorm:"default:false"`
	Path      string    `json:"path" gorm:"-"` // Path is not stored in the database
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName sets the table name for the Repository model
func (Repository) TableName() string {
	return "repositories"
}

// RepositoryServiceImpl provides methods for interacting with repositories in the database
type RepositoryServiceImpl struct {
	db *gorm.DB
}

// NewRepositoryService creates a new repository service
func NewRepositoryService(db *gorm.DB) RepositoryService {
	return &RepositoryServiceImpl{db: db}
}

// Create inserts a new repository into the database
func (s *RepositoryServiceImpl) Create(repo *Repository) error {
	return s.db.Create(repo).Error
}

// GetByID retrieves a repository by its ID
func (s *RepositoryServiceImpl) GetByID(id uint) (*Repository, error) {
	var repo Repository
	err := s.db.Preload("Owner").First(&repo, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("repository not found")
		}
		return nil, err
	}
	return &repo, nil
}

// GetByUsername retrieves a repository by username and repository name
func (s *RepositoryServiceImpl) GetByUsername(username, repoName string) (*Repository, error) {
	var repo Repository
	err := s.db.Joins("JOIN users ON users.id = repositories.owner_id").
		Where("users.username = ? AND repositories.name = ?", username, repoName).
		Preload("Owner").
		First(&repo).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("repository not found")
		}
		return nil, err
	}
	return &repo, nil
}

// Update updates an existing repository in the database
func (s *RepositoryServiceImpl) Update(repo *Repository) error {
	return s.db.Save(repo).Error
}

// Delete removes a repository from the database
func (s *RepositoryServiceImpl) Delete(id uint) error {
	return s.db.Delete(&Repository{}, id).Error
}

// ListByOwner retrieves repositories for a given owner with pagination
func (s *RepositoryServiceImpl) ListByOwner(ownerID uint, limit, offset int) ([]*Repository, error) {
	var repos []*Repository
	err := s.db.Where("owner_id = ?", ownerID).
		Preload("Owner").
		Limit(limit).
		Offset(offset).
		Order("name").
		Find(&repos).Error
	return repos, err
}
