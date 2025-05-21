package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db"
)

var (
	// ErrRepoNotFound is returned when a repository does not exist
	ErrRepoNotFound = errors.New("repository not found")
	// ErrRepoAlreadyExists is returned when creating a repository that already exists
	ErrRepoAlreadyExists = errors.New("repository already exists")

	// repoLocks provides mutex locks for each repository to prevent concurrent modifications
	repoLocks = &sync.Map{}
)

// Manager handles filesystem operations for repositories
type Manager struct {
	cfg *config.Config
}

// NewManager creates a new repository manager
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg: cfg,
	}
}

// LockRepo acquires a lock for a repository
func (m *Manager) LockRepo(repoPath string) func() {
	value, _ := repoLocks.LoadOrStore(repoPath, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return func() { mutex.Unlock() }
}

// GetRepoPath returns the filesystem path for a repository
func (m *Manager) GetRepoPath(repo *db.Repository) string {
	return repo.Path
}

// RepoExists checks if a repository exists at the given path
func (m *Manager) RepoExists(path string) bool {
	// Check if .vec directory exists
	vecDir := filepath.Join(path, ".vec")
	info, err := os.Stat(vecDir)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// CreateRepo creates a new bare repository
func (m *Manager) CreateRepo(owner *db.User, repoName string) (string, error) {
	// Generate repository path using owner's username and repository name
	ownerPath := filepath.Join(m.cfg.RepoBasePath, owner.Username)
	repoPath := filepath.Join(ownerPath, repoName+".vec")

	// Check if repository directory already exists
	if _, err := os.Stat(repoPath); err == nil {
		return "", ErrRepoAlreadyExists
	}

	// Create owner directory if it doesn't exist
	if err := os.MkdirAll(ownerPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create owner directory: %w", err)
	}

	// Initialize bare repository
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create repository directory: %w", err)
	}

	// Create .vec directory
	vecDir := filepath.Join(repoPath, ".vec")
	if err := os.Mkdir(vecDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create .vec directory: %w", err)
	}

	// Create basic repository structure
	dirs := []string{
		filepath.Join(vecDir, "objects"),
		filepath.Join(vecDir, "refs", "heads"),
		filepath.Join(vecDir, "refs", "tags"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create HEAD file pointing to master branch
	headFile := filepath.Join(vecDir, "HEAD")
	if err := os.WriteFile(headFile, []byte("ref: refs/heads/main\n"), 0644); err != nil {
		return "", fmt.Errorf("failed to create HEAD file: %w", err)
	}

	// Create config file
	configFile := filepath.Join(vecDir, "config")
	configContent := []byte("[core]\n\tbare = true\n")
	if err := os.WriteFile(configFile, configContent, 0644); err != nil {
		return "", fmt.Errorf("failed to create config file: %w", err)
	}

	return repoPath, nil
}

// DeleteRepo deletes a repository
func (m *Manager) DeleteRepo(repo *db.Repository) error {
	// Acquire lock for this repo
	unlock := m.LockRepo(repo.Path)
	defer unlock()

	// Check if repository exists
	if !m.RepoExists(repo.Path) {
		return ErrRepoNotFound
	}

	// Delete the repository directory
	if err := os.RemoveAll(repo.Path); err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}

	return nil
}

// GetRefs returns a list of all references in a repository
func (m *Manager) GetRefs(repo *db.Repository) (map[string]string, error) {
	refs := make(map[string]string)

	// Get path to refs directory
	refsDir := filepath.Join(repo.Path, ".vec", "refs")

	// Walk through refs directory to find all references
	err := filepath.Walk(refsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Read reference file
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Get relative path from refs directory
		relPath, err := filepath.Rel(refsDir, path)
		if err != nil {
			return err
		}

		// Store reference
		refName := filepath.ToSlash(relPath)
		refs[refName] = string(data)

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Get HEAD reference
	headPath := filepath.Join(repo.Path, ".vec", "HEAD")
	headData, err := os.ReadFile(headPath)
	if err == nil {
		refs["HEAD"] = string(headData)
	}

	return refs, nil
}
