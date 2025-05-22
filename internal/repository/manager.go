package repository

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
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
	cfg    *config.Config
	fs     *FS
	refMgr *RefManager
}

// NewManager creates a new repository manager
func NewManager(cfg *config.Config) *Manager {
	fs := NewFS()
	refMgr := NewRefManager(fs)

	return &Manager{
		cfg:    cfg,
		fs:     fs,
		refMgr: refMgr,
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
func (m *Manager) GetRepoPath(ownerOrRepo interface{}, repoName ...string) string {
	// If passed a repository object
	if repo, ok := ownerOrRepo.(*models.Repository); ok {
		return repo.Path
	}

	// If passed owner and repo name strings
	if owner, ok := ownerOrRepo.(string); ok && len(repoName) > 0 {
		// Don't append .vec extension - use the repo name as is
		return filepath.Join(m.cfg.RepoBasePath, owner, repoName[0])
	}

	// Default case (should not happen)
	return ""
}

// RepositoryExists checks if a repository exists
func (m *Manager) RepositoryExists(owner, repoName string) bool {
	repoPath := m.GetRepoPath(owner, repoName)
	log.Printf("RepositoryExists: Checking existence of repo at path: %s", repoPath)
	return m.RepoExists(repoPath)
}

// RepoExists checks if a repository exists at the given path
func (m *Manager) RepoExists(path string) bool {
	// Check if .vec directory exists
	vecDir := filepath.Join(path, ".vec")
	info, err := os.Stat(vecDir)
	log.Printf("RepoExists: Checking .vec directory at: %s, err: %v", vecDir, err)
	if err != nil {
		return false
	}
	isDir := info.IsDir()
	log.Printf("RepoExists: .vec directory exists and isDir: %v", isDir)
	return isDir
}

// CreateRepo creates a new bare repository
func (m *Manager) CreateRepo(owner *models.User, repoName string) (string, error) {
	// Generate repository path using owner's username and repository name
	ownerPath := filepath.Join(m.cfg.RepoBasePath, owner.Username)
	repoPath := filepath.Join(ownerPath, repoName+".vec")

	// Check if repository directory already exists
	if _, err := os.Stat(repoPath); err == nil {
		return "", ErrRepoAlreadyExists
	}

	// Create owner directory if it doesn't exist
	if err := m.fs.CreateDirectory(ownerPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create owner directory: %w", err)
	}

	// Initialize bare repository
	if err := m.fs.CreateDirectory(repoPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create repository directory: %w", err)
	}

	// Create .vec directory
	vecDir := filepath.Join(repoPath, ".vec")
	if err := m.fs.CreateDirectory(vecDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create .vec directory: %w", err)
	}

	// Create basic repository structure
	dirs := []string{
		filepath.Join(vecDir, "objects"),
		filepath.Join(vecDir, "refs", "heads"),
		filepath.Join(vecDir, "refs", "tags"),
	}

	for _, dir := range dirs {
		if err := m.fs.CreateDirectory(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create a Repository model for reference operations
	repo := &models.Repository{
		Path: repoPath,
	}

	// Create HEAD file pointing to main branch (using RefManager)
	if err := m.refMgr.CreateRef(repo, "HEAD", "refs/heads/main", true); err != nil {
		return "", fmt.Errorf("failed to create HEAD reference: %w", err)
	}

	// Create config file
	configFile := filepath.Join(vecDir, "config")
	configContent := []byte("[core]\n\tbare = true\n")
	if err := m.fs.CreateFile(configFile, configContent, 0644); err != nil {
		return "", fmt.Errorf("failed to create config file: %w", err)
	}

	return repoPath, nil
}

// DeleteRepo deletes a repository
func (m *Manager) DeleteRepo(repo *models.Repository) error {
	// Acquire lock for this repo
	unlock := m.LockRepo(repo.Path)
	defer unlock()

	// Check if repository exists
	if !m.RepoExists(repo.Path) {
		return ErrRepoNotFound
	}

	// Delete the repository directory using FS
	if err := m.fs.DeleteDirectory(repo.Path); err != nil {
		return fmt.Errorf("failed to delete repository: %w", err)
	}

	return nil
}

// GetRefs returns a list of all references in a repository
func (m *Manager) GetRefs(repo *models.Repository) (map[string]string, error) {
	refs := make(map[string]string)

	// Use RefManager to list all references
	allRefs, err := m.refMgr.ListRefs(repo, "")
	if err != nil {
		return nil, err
	}

	// Convert Reference objects to map
	for _, ref := range allRefs {
		refs[ref.Name] = ref.Value
	}

	return refs, nil
}

// CreateBranch creates a new branch in a repository
func (m *Manager) CreateBranch(repo *models.Repository, branchName, targetCommit string) error {
	// Validate branch name
	if branchName == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	// Create the branch reference (non-symbolic)
	branchRef := fmt.Sprintf("refs/heads/%s", branchName)
	return m.refMgr.CreateRef(repo, branchRef, targetCommit, false)
}

// DeleteBranch deletes a branch from a repository
func (m *Manager) DeleteBranch(repo *models.Repository, branchName string) error {
	// Validate branch name
	if branchName == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	// Format the branch reference name
	branchRef := fmt.Sprintf("refs/heads/%s", branchName)

	// Check if it's the current branch
	headRef, err := m.refMgr.GetRef(repo, "HEAD")
	if err == nil && headRef.Symbolic && headRef.Value == branchRef {
		return fmt.Errorf("cannot delete the current branch")
	}

	// Delete the branch reference
	return m.refMgr.DeleteRef(repo, branchRef)
}

// CreateTag creates a new tag in a repository
func (m *Manager) CreateTag(repo *models.Repository, tagName, targetCommit string) error {
	// Validate tag name
	if tagName == "" {
		return fmt.Errorf("tag name cannot be empty")
	}

	// Create the tag reference (non-symbolic)
	tagRef := fmt.Sprintf("refs/tags/%s", tagName)
	return m.refMgr.CreateRef(repo, tagRef, targetCommit, false)
}

// DeleteTag deletes a tag from a repository
func (m *Manager) DeleteTag(repo *models.Repository, tagName string) error {
	// Validate tag name
	if tagName == "" {
		return fmt.Errorf("tag name cannot be empty")
	}

	// Format the tag reference name
	tagRef := fmt.Sprintf("refs/tags/%s", tagName)

	// Delete the tag reference
	return m.refMgr.DeleteRef(repo, tagRef)
}

// UpdateHead updates the HEAD reference to point to a different branch
func (m *Manager) UpdateHead(repo *models.Repository, branchName string) error {
	// Format the branch reference name
	branchRef := fmt.Sprintf("refs/heads/%s", branchName)

	// Check if the branch exists
	_, err := m.refMgr.GetRef(repo, branchRef)
	if err != nil {
		return fmt.Errorf("branch %s does not exist: %w", branchName, err)
	}

	// Update HEAD to point to the new branch
	return m.refMgr.CreateRef(repo, "HEAD", branchRef, true)
}

// SyncRepository ensures that a repository exists on disk
// If the repository doesn't exist, it creates the basic structure
func (m *Manager) SyncRepository(repo *models.Repository, ownerUser *models.User) error {
	// Check if repository exists on disk
	if m.RepoExists(repo.Path) {
		return nil // Repository already exists
	}

	// Repository doesn't exist, create the basic structure
	// Create owner directory if needed
	ownerDir := filepath.Dir(repo.Path)
	if err := m.fs.CreateDirectory(ownerDir, 0755); err != nil {
		return fmt.Errorf("failed to create owner directory: %w", err)
	}

	// Create repository directory
	if err := m.fs.CreateDirectory(repo.Path, 0755); err != nil {
		return fmt.Errorf("failed to create repository directory: %w", err)
	}

	// Create .vec directory
	vecDir := filepath.Join(repo.Path, ".vec")
	if err := m.fs.CreateDirectory(vecDir, 0755); err != nil {
		return fmt.Errorf("failed to create .vec directory: %w", err)
	}

	// Create basic repository structure
	dirs := []string{
		filepath.Join(vecDir, "objects"),
		filepath.Join(vecDir, "objects", "info"),
		filepath.Join(vecDir, "objects", "pack"),
		filepath.Join(vecDir, "refs", "heads"),
		filepath.Join(vecDir, "refs", "tags"),
		filepath.Join(vecDir, "logs"),
		filepath.Join(vecDir, "logs", "refs", "heads"),
	}

	for _, dir := range dirs {
		if err := m.fs.CreateDirectory(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create empty files
	emptyFiles := []string{
		filepath.Join(vecDir, "objects", "info", "alternates"),
		filepath.Join(vecDir, "objects", "info", "packs"),
	}

	for _, file := range emptyFiles {
		if err := m.fs.CreateFile(file, []byte{}, 0644); err != nil {
			return fmt.Errorf("failed to create file %s: %w", file, err)
		}
	}

	// Create HEAD file pointing to main branch
	headPath := filepath.Join(vecDir, "HEAD")
	headContent := []byte("ref: refs/heads/main\n")
	if err := m.fs.CreateFile(headPath, headContent, 0644); err != nil {
		return fmt.Errorf("failed to create HEAD file: %w", err)
	}

	// Create config file
	configFile := filepath.Join(vecDir, "config")
	configContent := []byte("[core]\n\tbare = true\n")
	if err := m.fs.CreateFile(configFile, configContent, 0644); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	// Instead of creating refs with all zeros, we'll leave it empty
	// InfoRefsHandler will return an empty refs map, which is valid for an empty repository

	return nil
}
