package core

import (
	"fmt"
)

// CreateBlobRepo creates a new blob object using Repository context.
func (repo *Repository) CreateBlob(content []byte) (string, error) {
	// Use WriteObject to handle hashing, header formatting, and writing.
	hash, err := repo.WriteObject("blob", content)
	if err != nil {
		return "", ObjectError(fmt.Sprintf("failed to create blob object: %s", err.Error()), err)
	}
	return hash, nil
}

// CreateBlob creates a new blob object using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateBlob(repoRoot string, content []byte) (string, error) {
	// Create a temporary Repository object
	repo := NewRepository(repoRoot)
	return repo.CreateBlob(content)
}

// GetBlobRepo retrieves a blob object by its hash using Repository context.
func (repo *Repository) GetBlob(hash string) ([]byte, error) {
	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		// ReadObject already returns a categorized error (e.g., if not found or format is bad)
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, fmt.Sprintf("blob %s", hash))
		}
		return nil, ObjectError(fmt.Sprintf("failed to read blob %s: %s", hash, err.Error()), err)
	}

	if objectType != "blob" {
		return nil, ObjectError(fmt.Sprintf("object %s is not a blob, but a %s", hash, objectType), nil)
	}

	return data, nil
}

// GetBlob retrieves a blob object by its hash using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func GetBlob(repoRoot string, hash string) ([]byte, error) {
	// Create a temporary Repository object
	repo := NewRepository(repoRoot)
	return repo.GetBlob(hash)
}
