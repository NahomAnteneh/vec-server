package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

var (
	// ErrReferenceNotFound is returned when a reference does not exist
	ErrReferenceNotFound = errors.New("reference not found")

	// ErrInvalidReference is returned when a reference name or value is invalid
	ErrInvalidReference = errors.New("invalid reference")

	// refLocks provides mutex locks for each reference to prevent concurrent modifications
	refLocks = &sync.Map{}
)

// RefType represents the type of reference
type RefType string

const (
	// RefTypeBranch represents a branch reference
	RefTypeBranch RefType = "heads"

	// RefTypeTag represents a tag reference
	RefTypeTag RefType = "tags"
)

// Reference represents a git reference
type Reference struct {
	Name     string // Full name of the reference (e.g., refs/heads/main)
	Value    string // Hash or reference that it points to
	RefType  RefType
	Symbolic bool // Whether this is a symbolic reference
}

// RefManager handles reference operations for repositories
type RefManager struct {
	fs *FS
}

// NewRefManager creates a new reference manager
func NewRefManager(fs *FS) *RefManager {
	return &RefManager{
		fs: fs,
	}
}

// LockRef acquires a lock for a specific reference
func (rm *RefManager) LockRef(repoPath, refName string) func() {
	key := fmt.Sprintf("%s:%s", repoPath, refName)
	value, _ := refLocks.LoadOrStore(key, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return func() { mutex.Unlock() }
}

// GetRefPath returns the filesystem path for a reference
func (rm *RefManager) GetRefPath(repo *models.Repository, refName string) string {
	// Handle special case for HEAD
	if refName == "HEAD" {
		return filepath.Join(repo.Path, ".vec", "HEAD")
	}

	// If the reference already contains "refs/", use it directly
	if strings.HasPrefix(refName, "refs/") {
		return filepath.Join(repo.Path, ".vec", refName)
	}

	// Otherwise, assume it's a branch name and prefix with refs/heads/
	return filepath.Join(repo.Path, ".vec", "refs", "heads", refName)
}

// ParseRefName parses a reference name into its components
func (rm *RefManager) ParseRefName(refName string) (RefType, string, error) {
	// Handle HEAD as a special case
	if refName == "HEAD" {
		return "", refName, nil
	}

	// Check if it has the proper format
	if !strings.HasPrefix(refName, "refs/") {
		return "", "", ErrInvalidReference
	}

	// Split the reference name
	parts := strings.SplitN(strings.TrimPrefix(refName, "refs/"), "/", 2)
	if len(parts) != 2 {
		return "", "", ErrInvalidReference
	}

	refType := RefType(parts[0])
	shortName := parts[1]

	// Validate reference type
	if refType != RefTypeBranch && refType != RefTypeTag {
		return "", "", ErrInvalidReference
	}

	return refType, shortName, nil
}

// GetRef retrieves a reference
func (rm *RefManager) GetRef(repo *models.Repository, refName string) (*Reference, error) {
	refPath := rm.GetRefPath(repo, refName)

	// Check if reference exists
	if _, err := os.Stat(refPath); os.IsNotExist(err) {
		return nil, ErrReferenceNotFound
	}

	// Read reference
	data, err := rm.fs.ReadFile(refPath)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))

	// Handle symbolic references
	if strings.HasPrefix(content, "ref: ") {
		refValue := strings.TrimPrefix(content, "ref: ")

		refType, _, err := rm.ParseRefName(refName)
		if err != nil {
			return nil, err
		}

		return &Reference{
			Name:     refName,
			Value:    refValue,
			RefType:  refType,
			Symbolic: true,
		}, nil
	}

	// Handle direct references
	refType, _, err := rm.ParseRefName(refName)
	if err != nil {
		return nil, err
	}

	return &Reference{
		Name:     refName,
		Value:    content,
		RefType:  refType,
		Symbolic: false,
	}, nil
}

// CreateRef creates a new reference
func (rm *RefManager) CreateRef(repo *models.Repository, refName, value string, symbolic bool) error {
	refPath := rm.GetRefPath(repo, refName)

	// Lock the reference
	unlock := rm.LockRef(repo.Path, refName)
	defer unlock()

	// Determine content to write
	var content string
	if symbolic {
		content = fmt.Sprintf("ref: %s\n", value)
	} else {
		content = fmt.Sprintf("%s\n", value)
	}

	// Write the reference atomically
	return rm.fs.AtomicWriteFile(refPath, []byte(content), 0644)
}

// UpdateRef updates an existing reference
func (rm *RefManager) UpdateRef(repo *models.Repository, refName, newValue string, symbolic bool) error {
	// Check if reference exists
	if _, err := rm.GetRef(repo, refName); err != nil {
		return err
	}

	// Update the reference (same as create, but we've verified it exists)
	return rm.CreateRef(repo, refName, newValue, symbolic)
}

// DeleteRef deletes a reference
func (rm *RefManager) DeleteRef(repo *models.Repository, refName string) error {
	refPath := rm.GetRefPath(repo, refName)

	// Lock the reference
	unlock := rm.LockRef(repo.Path, refName)
	defer unlock()

	// Check if reference exists
	if _, err := os.Stat(refPath); os.IsNotExist(err) {
		return ErrReferenceNotFound
	}

	// Delete the reference
	return rm.fs.DeleteFile(refPath)
}

// ListRefs lists all references in a repository
func (rm *RefManager) ListRefs(repo *models.Repository, refType RefType) ([]*Reference, error) {
	var refs []*Reference
	refsPath := filepath.Join(repo.Path, ".vec", "refs")

	// If a specific reference type is provided, narrow down the path
	if refType != "" {
		refsPath = filepath.Join(refsPath, string(refType))
	}

	// Walk through the refs directory
	err := filepath.Walk(refsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip invalid entries but continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get relative path to construct reference name
		relPath, err := filepath.Rel(filepath.Join(repo.Path, ".vec"), path)
		if err != nil {
			return nil
		}

		// Normalize path separators
		refName := filepath.ToSlash(relPath)

		// Get reference details
		ref, err := rm.GetRef(repo, refName)
		if err != nil {
			return nil
		}

		refs = append(refs, ref)
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Add HEAD if listing all references
	if refType == "" {
		headRef, err := rm.GetRef(repo, "HEAD")
		if err == nil {
			refs = append(refs, headRef)
		}
	}

	return refs, nil
}

// TransactionFunc defines a function that modifies references in a transaction
type TransactionFunc func(tx *RefTransaction) error

// RefTransaction represents a transaction for updating multiple references
type RefTransaction struct {
	rm       *RefManager
	repo     *models.Repository
	changes  map[string]string
	symbolic map[string]bool
}

// NewTransaction creates a new reference transaction
func (rm *RefManager) NewTransaction(repo *models.Repository) *RefTransaction {
	return &RefTransaction{
		rm:       rm,
		repo:     repo,
		changes:  make(map[string]string),
		symbolic: make(map[string]bool),
	}
}

// Update adds an update to a transaction
func (tx *RefTransaction) Update(refName, value string, symbolic bool) {
	tx.changes[refName] = value
	tx.symbolic[refName] = symbolic
}

// Delete adds a deletion to a transaction
func (tx *RefTransaction) Delete(refName string) {
	tx.changes[refName] = ""
}

// Execute executes all reference changes in a transaction
func (tx *RefTransaction) Execute() error {
	// Lock all references involved in the transaction
	unlocks := make([]func(), 0, len(tx.changes))
	for refName := range tx.changes {
		unlock := tx.rm.LockRef(tx.repo.Path, refName)
		unlocks = append(unlocks, unlock)
	}

	// Ensure all locks are released
	defer func() {
		for _, unlock := range unlocks {
			unlock()
		}
	}()

	// Process all changes
	for refName, value := range tx.changes {
		if value == "" {
			// Delete reference
			if err := tx.rm.DeleteRef(tx.repo, refName); err != nil {
				return err
			}
		} else {
			// Create or update reference
			symbolic := tx.symbolic[refName]
			if err := tx.rm.CreateRef(tx.repo, refName, value, symbolic); err != nil {
				return err
			}
		}
	}

	return nil
}

// RunTransaction runs a transaction with a supplied function
func (rm *RefManager) RunTransaction(repo *models.Repository, fn TransactionFunc) error {
	tx := rm.NewTransaction(repo)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Execute()
}
