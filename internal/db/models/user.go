package models

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User represents a user in the system with authentication information
type User struct {
	ID           uint      `json:"id" gorm:"primarykey"`
	Username     string    `json:"username" gorm:"uniqueIndex;size:255;not null"`
	Email        string    `json:"email" gorm:"uniqueIndex;size:255;not null"`
	PasswordHash string    `json:"-" gorm:"size:255;not null"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NewUser creates a new user with the given username, email, and password
func NewUser(username, email, password string) (*User, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	if email == "" {
		return nil, errors.New("email cannot be empty")
	}

	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
	}, nil
}

// CheckPassword verifies if the provided password matches the stored hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// UpdatePassword updates the user's password
func (u *User) UpdatePassword(password string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hashedPassword)
	return nil
}

// UserService provides methods for interacting with users in the database
type UserService struct {
	db *gorm.DB
}

// NewUserService creates a new user service with the given database connection
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// Create inserts a new user into the database
func (s *UserService) Create(user *User) error {
	return s.db.Create(user).Error
}

// GetByID retrieves a user by their ID
func (s *UserService) GetByID(id uint) (*User, error) {
	var user User
	err := s.db.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByUsername retrieves a user by their username
func (s *UserService) GetByUsername(username string) (*User, error) {
	var user User
	err := s.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// Update updates an existing user in the database
func (s *UserService) Update(user *User) error {
	return s.db.Save(user).Error
}

// Delete removes a user from the database
func (s *UserService) Delete(id uint) error {
	return s.db.Delete(&User{}, id).Error
}

// List retrieves all users with pagination
func (s *UserService) List(limit, offset int) ([]*User, error) {
	var users []*User
	err := s.db.Limit(limit).Offset(offset).Order("username").Find(&users).Error
	return users, err
}
