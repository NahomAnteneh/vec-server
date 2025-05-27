package core

import (
	"errors"
	"fmt"
)

// Standard error categories for Vec operations
const (
	ErrCategoryRepository = "repository"
	ErrCategoryConfig     = "config"
	ErrCategoryObject     = "object"
	ErrCategoryRef        = "reference"
	ErrCategoryFS         = "filesystem"
	ErrCategoryIndex      = "index"
	ErrCategoryRemote     = "remote"
	ErrCategoryNetwork    = "network"
	ErrCategoryMerge      = "merge"
)

// Sentinel errors for common conditions
var (
	ErrDataNotFound   = errors.New("data not found")
	ErrNotARepository = errors.New("not a repository")
	// Consider adding ErrDataAlreadyExists = errors.New("data already exists") if needed
)

// NewError creates a standardized error with a category prefix
func NewError(category, message string, err error) error {
	if err != nil {
		return fmt.Errorf("%s error: %s: %w", category, message, err)
	}
	return fmt.Errorf("%s error: %s", category, message)
}

// RepositoryError creates a standardized repository error
func RepositoryError(message string, err error) error {
	return NewError(ErrCategoryRepository, message, err)
}

// ConfigError creates a standardized configuration error
func ConfigError(message string, err error) error {
	return NewError(ErrCategoryConfig, message, err)
}

// ObjectError creates a standardized object error
func ObjectError(message string, err error) error {
	return NewError(ErrCategoryObject, message, err)
}

// RefError creates a standardized reference error
func RefError(message string, err error) error {
	return NewError(ErrCategoryRef, message, err)
}

// FSError creates a standardized filesystem error
func FSError(message string, err error) error {
	return NewError(ErrCategoryFS, message, err)
}

// IndexError creates a standardized index error
func IndexError(message string, err error) error {
	return NewError(ErrCategoryIndex, message, err)
}

// RemoteError creates a standardized remote error
func RemoteError(message string, err error) error {
	return NewError(ErrCategoryRemote, message, err)
}

// NetworkError creates a standardized network error
func NetworkError(message string, err error) error {
	return NewError(ErrCategoryNetwork, message, err)
}

// MergeError creates a standardized merge error
func MergeError(message string, err error) error {
	return NewError(ErrCategoryMerge, message, err)
}

// IsErrNotFound checks if an error is a "not found" error
func IsErrNotFound(err error) bool {
	return errors.Is(err, ErrDataNotFound)
}

// IsErrNotRepo checks if an error indicates "not a repository"
func IsErrNotRepo(err error) bool {
	return errors.Is(err, ErrNotARepository)
}

// NotFoundError creates a standardized "not found" error
func NotFoundError(category, item string) error {
	return NewError(category, fmt.Sprintf("%s not found", item), ErrDataNotFound)
}

// AlreadyExistsError creates a standardized "already exists" error
func AlreadyExistsError(category, item string) error {
	return NewError(category, fmt.Sprintf("%s already exists", item), nil)
}
