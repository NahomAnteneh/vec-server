package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	// TokenExpiration defines how long a token remains valid
	TokenExpiration = 24 * time.Hour
)

var (
	// ErrInvalidCredentials is returned when authentication fails
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrTokenExpired is returned when a token has expired
	ErrTokenExpired = errors.New("token has expired")
	// ErrInvalidToken is returned when a token is invalid
	ErrInvalidToken = errors.New("invalid token")
)

// Claims defines the JWT claims structure
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// AuthenticateUser verifies user credentials
func AuthenticateUser(db *gorm.DB, username, password string) (*models.User, error) {
	var user models.User

	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, result.Error
	}

	if !CheckPasswordHash(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	return &user, nil
}

// AuthToken represents an authentication token
type AuthToken struct {
	ID          uint        `json:"id" gorm:"primarykey"`
	UserID      uint        `json:"user_id" gorm:"not null"`
	User        models.User `json:"user" gorm:"foreignKey:UserID"`
	TokenHash   string      `json:"-" gorm:"size:255;not null"`
	Description string      `json:"description" gorm:"size:255"`
	ExpiresAt   *time.Time  `json:"expires_at"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// CreateAuthToken generates a new authentication token for a user
func CreateAuthToken(db *gorm.DB, userID uint, description string) (*AuthToken, string, error) {
	// Generate a random token
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return nil, "", err
	}

	tokenStr := hex.EncodeToString(token)

	// Hash the token for storage
	hash, err := HashPassword(tokenStr)
	if err != nil {
		return nil, "", err
	}

	// Set expiration date
	expiresAt := time.Now().Add(90 * 24 * time.Hour) // 90 days

	// Create token record
	authToken := &AuthToken{
		UserID:      userID,
		TokenHash:   hash,
		Description: description,
		ExpiresAt:   &expiresAt,
	}

	if err := db.Create(authToken).Error; err != nil {
		return nil, "", err
	}

	return authToken, tokenStr, nil
}

// VerifyAuthToken checks if a personal access token is valid
func VerifyAuthToken(db *gorm.DB, tokenStr string) (*models.User, error) {
	var tokens []AuthToken

	// Get all tokens - we'll need to check each hash
	if err := db.Preload("User").Find(&tokens).Error; err != nil {
		return nil, err
	}

	for _, token := range tokens {
		// Skip expired tokens
		if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
			continue
		}

		// Check if token matches
		if CheckPasswordHash(tokenStr, token.TokenHash) {
			return &token.User, nil
		}
	}

	return nil, ErrInvalidCredentials
}
