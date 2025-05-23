package repository

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// Errors for repository operations
var (
	ErrRepoNotFound      = errors.New("repository not found")
	ErrRepoAlreadyExists = errors.New("repository already exists")
	ErrInvalidRepoName   = errors.New("invalid repository name")
)

// repoLocks provides mutex locks for each repository to prevent concurrent modifications
var repoLocks = &sync.Map{}

// Manager handles filesystem operations for repositories
type Manager struct {
	cfg         *config.Config
	fs          *FS
	refMgr      *RefManager
	logger      *log.Logger
	syncManager *SyncManager
}

// NewManager creates a new repository manager
func NewManager(cfg *config.Config, logger *log.Logger) *Manager {
	fs := NewFS()
	refMgr := NewRefManager(fs)
	return &Manager{
		cfg:    cfg,
		fs:     fs,
		refMgr: refMgr,
		logger: logger,
	}
}

// SetSyncManager sets the sync manager for database operations
func (m *Manager) SetSyncManager(syncManager *SyncManager) {
	m.syncManager = syncManager
}

// GetSyncManager returns the sync manager for database operations
func (m *Manager) GetSyncManager() *SyncManager {
	return m.syncManager
}

// LockRepo acquires a lock for a repository
func (m *Manager) LockRepo(repoPath string) func() {
	value, _ := repoLocks.LoadOrStore(repoPath, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return func() { mutex.Unlock() }
}

// GetRepoPath returns the filesystem path for a repository
func (m *Manager) GetRepoPath(ownerOrRepo interface{}, repoName ...string) (string, error) {
	var owner, repo string
	if repoObj, ok := ownerOrRepo.(*models.Repository); ok {
		return repoObj.Path, nil
	} else if ownerStr, ok := ownerOrRepo.(string); ok && len(repoName) > 0 {
		owner = ownerStr
		repo = repoName[0]
	} else {
		return "", fmt.Errorf("invalid owner or repository name")
	}

	// Validate owner and repo name
	if owner == "" || strings.ContainsAny(owner, "/\\:") || strings.Contains(owner, "..") {
		return "", fmt.Errorf("invalid owner: %s", owner)
	}
	if repo == "" || strings.ContainsAny(repo, "/\\:") || strings.Contains(repo, "..") {
		return "", ErrInvalidRepoName
	}

	path := filepath.Join(m.cfg.RepoBasePath, owner, repo)
	if err := m.fs.ValidatePath(m.cfg.RepoBasePath, filepath.Join(owner, repo)); err != nil {
		return "", fmt.Errorf("invalid repository path: %w", err)
	}
	return path, nil
}

// RepositoryExists checks if a repository exists
func (m *Manager) RepositoryExists(owner, repoName string) (bool, error) {
	repoPath, err := m.GetRepoPath(owner, repoName)
	if err != nil {
		return false, err
	}
	m.logger.Printf("Checking existence of repo at path: %s", repoPath)
	return m.RepoExists(repoPath), nil
}

// RepoExists checks if a repository exists at the given path
func (m *Manager) RepoExists(path string) bool {
	vecDir := filepath.Join(path, ".vec")
	info, err := os.Stat(vecDir)
	if err != nil {
		m.logger.Printf("RepoExists: No .vec directory at %s: %v", vecDir, err)
		return false
	}
	return info.IsDir()
}

// createRepoStructure sets up the repository structure
func (m *Manager) createRepoStructure(repo *models.Repository) error {
	vecDir := filepath.Join(repo.Path, ".vec")

	// Create subdirectories
	subDirs := []string{
		filepath.Join(vecDir, "objects"),
		filepath.Join(vecDir, "objects", "pack"),
		filepath.Join(vecDir, "objects", "info"),
		filepath.Join(vecDir, "refs", "heads"),
		filepath.Join(vecDir, "refs", "remotes"),
		filepath.Join(vecDir, "logs", "refs", "heads"),
		filepath.Join(vecDir, "logs"),
	}

	for _, subDir := range subDirs {
		if err := m.fs.CreateDirectory(subDir, 0755); err != nil {
			return fmt.Errorf("failed to create subdirectory %s: %w", subDir, err)
		}
	}

	// Create common files
	files := map[string]string{
		filepath.Join(vecDir, "objects", "info", "packs"):      "",
		filepath.Join(vecDir, "objects", "info", "alternates"): "",
		filepath.Join(vecDir, "HEAD"):                          "ref: refs/heads/main\n",
		filepath.Join(vecDir, "logs", "HEAD"):                  "",
		filepath.Join(vecDir, "refs", "heads", "main"):         "",
	}

	for file, content := range files {
		if err := m.fs.AtomicWriteFile(file, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to create file %s: %w", file, err)
		}
	}

	// Create config file
	configFile := filepath.Join(vecDir, "config")
	config := "[core]\n\tbare = true\n"
	if err := m.fs.AtomicWriteFile(configFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	return nil
}

// CreateRepo creates a new bare repository
func (m *Manager) CreateRepo(owner *models.User, repoName string) (string, error) {
	if owner == nil || owner.Username == "" {
		return "", fmt.Errorf("invalid owner: username cannot be empty")
	}
	if repoName == "" || strings.ContainsAny(repoName, "/\\:") || strings.Contains(repoName, "..") {
		return "", ErrInvalidRepoName
	}

	repoPath, err := m.GetRepoPath(owner.Username, repoName)
	if err != nil {
		return "", err
	}

	unlock := m.LockRepo(repoPath)
	defer unlock()

	if m.RepoExists(repoPath) {
		return "", ErrRepoAlreadyExists
	}

	ownerPath := filepath.Dir(repoPath)
	if err := m.fs.CreateDirectory(ownerPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create owner directory %s: %w", ownerPath, err)
	}

	if err := m.fs.CreateDirectory(repoPath, 0755); err != nil {
		return "", fmt.Errorf("directory %s is not empty", repoPath)
	}

	// Create .vec directory and structure
	if err := m.fs.CreateDirectory(filepath.Join(repoPath, ".vec"), 0755); err != nil {
		return "", fmt.Errorf("failed to create .vec directory: %w", err)
	}

	if err := m.createRepoStructure(&models.Repository{Path: repoPath}); err != nil {
		return "", err
	}

	m.logger.Printf("Initialized empty bare Vec repository in %s", repoPath)
	return repoPath, nil
}

// DeleteRepo deletes a repository
func (m *Manager) DeleteRepo(repo *models.Repository) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}

	unlock := m.LockRepo(repo.Path)
	defer unlock()
	defer repoLocks.Delete(repo.Path)

	if !m.RepoExists(repo.Path) {
		return ErrRepoNotFound
	}

	if err := m.fs.DeleteDirectory(repo.Path); err != nil {
		return fmt.Errorf("failed to delete repository %s: %w", repo.Path, err)
	}

	m.logger.Printf("Deleted repository %s", repo.Path)
	return nil
}

// GetRefs returns a list of all references in a repository
func (m *Manager) GetRefs(repo *models.Repository) (map[string]string, error) {
	if repo == nil || repo.Path == "" {
		return nil, fmt.Errorf("invalid repository")
	}

	refs, err := m.refMgr.ListRefs(repo, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list references for repo %s: %w", repo.Path, err)
	}

	result := make(map[string]string)
	for _, ref := range refs {
		result[ref.Name] = ref.Value
	}
	return result, nil
}

// GetRef retrieves a specific reference for a repository
func (m *Manager) GetRef(repo *models.Repository, refName string) (*Reference, error) {
	if repo == nil || repo.Path == "" {
		return nil, fmt.Errorf("invalid repository")
	}
	if refName == "" {
		return nil, fmt.Errorf("invalid reference name")
	}
	return m.refMgr.GetRef(repo, refName)
}

// RunTransaction runs a reference transaction for a repository
func (m *Manager) RunTransaction(repo *models.Repository, fn TransactionFunc) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	return m.refMgr.RunTransaction(repo, fn)
}

// CreateBranch creates a new branch in a repository
func (m *Manager) CreateBranch(repo *models.Repository, branchName, targetCommit string) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	if branchName == "" || strings.ContainsAny(branchName, "/\\:") || strings.Contains(branchName, "..") {
		return fmt.Errorf("invalid branch name: %s", branchName)
	}
	if !isValidCommitHash(targetCommit) {
		return fmt.Errorf("invalid commit hash: %s", targetCommit)
	}

	branchRef := fmt.Sprintf("refs/heads/%s", branchName)
	m.logger.Printf("Creating branch %s in repo %s", branchRef, repo.Path)
	return m.refMgr.CreateRef(repo, branchRef, targetCommit, false)
}

// DeleteBranch deletes a branch from a repository
func (m *Manager) DeleteBranch(repo *models.Repository, branchName string) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	if branchName == "" || strings.ContainsAny(branchName, "/\\:") ||

		strings.Contains(branchName, "..") {
		return fmt.Errorf("invalid branch name: %s", branchName)
	}

	branchRef := fmt.Sprintf("refs/heads/%s", branchName)
	headRef, err := m.refMgr.GetRef(repo, "HEAD")
	if err == nil && headRef.Symbolic && headRef.Value == branchRef {
		return fmt.Errorf("cannot delete the current branch: %s", branchName)
	}

	m.logger.Printf("Deleting branch %s in repo %s", branchRef, repo.Path)
	return m.refMgr.DeleteRef(repo, branchRef)
}

// CreateTag creates a new tag in a repository
func (m *Manager) CreateTag(repo *models.Repository, tagName, targetCommit string) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	if tagName == "" || strings.ContainsAny(tagName, "/\\:") || strings.Contains(tagName, "..") {
		return fmt.Errorf("invalid tag name: %s", tagName)
	}
	if !isValidCommitHash(targetCommit) {
		return fmt.Errorf("invalid commit hash: %s", targetCommit)
	}

	tagRef := fmt.Sprintf("refs/tags/%s", tagName)
	m.logger.Printf("Creating tag %s in repo %s", tagRef, repo.Path)
	return m.refMgr.CreateRef(repo, tagRef, targetCommit, false)
}

// DeleteTag deletes a tag from a repository
func (m *Manager) DeleteTag(repo *models.Repository, tagName string) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	if tagName == "" || strings.ContainsAny(tagName, "/\\:") || strings.Contains(tagName, "..") {
		return fmt.Errorf("invalid tag name: %s", tagName)
	}

	tagRef := fmt.Sprintf("refs/tags/%s", tagName)
	m.logger.Printf("Deleting tag %s in repo %s", tagRef, repo.Path)
	return m.refMgr.DeleteRef(repo, tagRef)
}

// UpdateHead updates the HEAD reference to point to a different branch
func (m *Manager) UpdateHead(repo *models.Repository, branchName string) error {
	if repo == nil || repo.Path == "" {
		return fmt.Errorf("invalid repository")
	}
	if branchName == "" || strings.ContainsAny(branchName, "/\\:") || strings.Contains(branchName, "..") {
		return fmt.Errorf("invalid branch name: %s", branchName)
	}

	branchRef := fmt.Sprintf("refs/heads/%s", branchName)
	if _, err := m.refMgr.GetRef(repo, branchRef); err != nil {
		return fmt.Errorf("branch %s does not exist: %w", branchName, err)
	}

	m.logger.Printf("Updating HEAD to %s in repo %s", branchRef, repo.Path)
	return m.refMgr.CreateRef(repo, "HEAD", branchRef, true)
}

// SyncRepository ensures that a repository exists on disk
func (m *Manager) SyncRepository(repo *models.Repository, ownerUser *models.User) error {
	if repo == nil || repo.Path == "" || ownerUser == nil || ownerUser.Username == "" {
		return fmt.Errorf("invalid repository or owner")
	}

	// Ensure repository exists on disk
	if !m.RepoExists(repo.Path) {
		m.logger.Printf("Syncing repository %s for owner %s", repo.Path, ownerUser.Username)
		if err := m.createRepoStructure(repo); err != nil {
			return err
		}
	}

	// If we have a sync manager, use it to sync database records
	if m.syncManager != nil {
		// Make sure the repository has its ID set for database operations
		if repo.ID == 0 {
			m.logger.Printf("Repository ID not set, looking up in database")
			repoService := m.syncManager.repoService
			dbRepo, err := repoService.GetByUsername(ownerUser.Username, repo.Name)
			if err != nil {
				return fmt.Errorf("failed to find repository in database: %w", err)
			}
			repo.ID = dbRepo.ID
		}

		m.logger.Printf("Syncing repository metadata to database for %s (ID: %d)", repo.Path, repo.ID)
		return m.syncManager.SyncRepository(repo)
	}

	return nil
}

// isValidCommitHash checks if a string is a valid SHA-1 or SHA-256 hash
func isValidCommitHash(hash string) bool {
	if len(hash) != 40 && len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ReadObject reads an object from the repository
func (m *Manager) ReadObject(repo *models.Repository, hash string) (string, []byte, error) {
	if repo == nil || repo.Path == "" {
		return "", nil, fmt.Errorf("invalid repository")
	}
	if hash == "" || !isValidCommitHash(hash) {
		return "", nil, fmt.Errorf("invalid object hash: %s", hash)
	}

	m.logger.Printf("Reading object %s from repo %s", hash, repo.Path)

	// Use core.ReadObject to read the object
	objectType, data, err := core.ReadObject(repo.Path, hash)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read object %s: %w", hash, err)
	}

	return objectType, data, nil
}
