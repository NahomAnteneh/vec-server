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

// Manager handles filesystem operations for repositories using the core package.
type Manager struct {
	cfg         *config.Config
	logger      *log.Logger
	syncManager *SyncManager // Remains, as it coordinates DB and core operations
}

// NewManager creates a new repository manager.
// It no longer initializes FS or RefManager, as operations will use the core package.
func NewManager(cfg *config.Config, logger *log.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger,
	}
}

// getCoreRepository is a helper to obtain a core.Repository instance.
// The repoPath must be the absolute path to the root of the repository.
func (m *Manager) getCoreRepository(repoPath string) *core.Repository {
	// core.NewRepository just sets up paths, it doesn't validate existence here.
	return core.NewRepository(repoPath)
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
// This path is the root of the working directory for the bare repository.
func (m *Manager) GetRepoPath(ownerName string, repoNameStr string) (string, error) {
	// Validate owner and repo name
	if ownerName == "" || strings.ContainsAny(ownerName, "/\\:") || strings.Contains(ownerName, "..") {
		return "", fmt.Errorf("invalid owner: %s", ownerName)
	}
	if repoNameStr == "" || strings.ContainsAny(repoNameStr, "/\\:") || strings.Contains(repoNameStr, "..") {
		return "", ErrInvalidRepoName
	}

	// Construct path using base path from config
	// Ensure this path is absolute and validated
	baseRepoPath := m.cfg.RepoBasePath
	if baseRepoPath == "" {
		return "", fmt.Errorf("repository base path is not configured")
	}

	repoPath := filepath.Join(baseRepoPath, ownerName, repoNameStr)

	// Basic validation that the path is within the configured base path
	// filepath.Clean and checking prefix is a simple way to prevent "../" escapes reaching outside baseRepoPath.
	cleanedRepoPath := filepath.Clean(repoPath)
	if !strings.HasPrefix(cleanedRepoPath, filepath.Clean(baseRepoPath)) {
		return "", fmt.Errorf("invalid repository path construction: %s attempts to escape base path %s", repoPath, baseRepoPath)
	}

	return cleanedRepoPath, nil
}

// RepositoryExists checks if a repository exists by looking for the .vec directory.
func (m *Manager) RepositoryExists(owner, repoName string) (bool, error) {
	repoPath, err := m.GetRepoPath(owner, repoName)
	if err != nil {
		return false, err
	}
	// A repository exists if its .vec directory is present.
	// core.NewRepository(repoPath).VecDir gives the path to .vec
	// We can use core.FileExists from the core/fs.go which is public.
	vecDirPath := filepath.Join(repoPath, core.VecDirName)
	return core.FileExists(vecDirPath), nil
}

// CreateRepo creates a new bare repository using core functionalities.
func (m *Manager) CreateRepo(ownerName string, repoNameStr string) (string, error) {
	if ownerName == "" {
		return "", fmt.Errorf("invalid owner: username cannot be empty")
	}
	if repoNameStr == "" {
		return "", ErrInvalidRepoName
	}

	repoPath, err := m.GetRepoPath(ownerName, repoNameStr)
	if err != nil {
		return "", err
	}

	unlock := m.LockRepo(repoPath)
	defer unlock()

	exists, err := m.RepositoryExists(ownerName, repoNameStr)
	if err != nil {
		return "", fmt.Errorf("failed to check repository existence: %w", err)
	}
	if exists {
		return "", ErrRepoAlreadyExists
	}

	// Ensure parent directory for the owner exists. core.CreateBareRepo expects the repoPath itself to be creatable.
	ownerPath := filepath.Dir(repoPath)
	if err := os.MkdirAll(ownerPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create owner directory %s: %w", ownerPath, err)
	}

	// core.CreateBareRepo will create the repoPath directory if it doesn't exist.
	cr := core.NewRepository(repoPath)
	if err := core.CreateBareRepo(cr); err != nil {
		// Attempt to clean up repoPath if CreateBareRepo failed partially
		// os.RemoveAll(repoPath) // Be cautious with this in case of non-empty dir from other sources
		return "", fmt.Errorf("failed to create bare repository using core: %w", err)
	}

	m.logger.Printf("Initialized empty Vec repository in %s", repoPath)
	return repoPath, nil
}

// DeleteRepo deletes a repository from the filesystem.
func (m *Manager) DeleteRepo(ownerName, repoNameStr string) error {
	repoPath, err := m.GetRepoPath(ownerName, repoNameStr)
	if err != nil {
		return err
	}

	unlock := m.LockRepo(repoPath)
	defer unlock()
	// It's important to also remove the lock from the map if the repo is deleted to prevent memory leak.
	defer repoLocks.Delete(repoPath)

	exists, _ := m.RepositoryExists(ownerName, repoNameStr) // Error can be ignored as we just need existence
	if !exists {
		return ErrRepoNotFound
	}

	if err := os.RemoveAll(repoPath); err != nil {
		return fmt.Errorf("failed to delete repository directory %s: %w", repoPath, err)
	}

	m.logger.Printf("Deleted repository %s/%s", ownerName, repoNameStr)
	return nil
}

// ReadObject directly uses core.ReadObject.
// repoPath is the root of the repository.
func (m *Manager) ReadObject(repoPath string, hash string) (string, []byte, error) {
	cr := core.NewRepository(repoPath)
	return core.ReadObject(cr, hash) // Pass *core.Repository instance
}

// WriteObject directly uses core.WriteObject.
// repoPath is the root of the repository.
func (m *Manager) WriteObject(repoPath string, objectType string, data []byte) (string, error) {
	cr := core.NewRepository(repoPath)
	return core.WriteObject(cr, objectType, data) // Pass *core.Repository instance
}

// GetBranches retrieves all branches for a repository.
// repoPath is the root of the repository.
func (m *Manager) GetBranches(repoPath string) (map[string]string, error) {
	cr := m.getCoreRepository(repoPath)
	branchNames, err := cr.GetAllBranches() // This is core.GetAllBranches(repoPath)
	if err != nil {
		// If it's a not found error for a new repo, return an empty map instead of an error
		if core.IsErrNotFound(err) {
			m.logger.Printf("GetBranches: Refs directory not found for %s, likely a new repository. Returning empty branch map.", repoPath)
			return make(map[string]string), nil
		}
		return nil, fmt.Errorf("failed to get branches from core: %w", err)
	}

	branches := make(map[string]string)
	for _, branchName := range branchNames {
		refPath := filepath.Join("refs", "heads", branchName) // Relative to .vec
		fullRefPath := filepath.Join(cr.VecDir, refPath)

		// Check if the file exists and has content
		if !core.FileExists(fullRefPath) {
			m.logger.Printf("Warning: branch ref file doesn't exist: %s", fullRefPath)
			continue
		}

		fileInfo, err := os.Stat(fullRefPath)
		if err != nil {
			m.logger.Printf("Warning: cannot stat branch ref file %s: %v", fullRefPath, err)
			continue
		}

		if fileInfo.Size() == 0 {
			m.logger.Printf("Warning: branch ref file is empty: %s", fullRefPath)

			// If this is the main branch and we have a HEAD commit, copy it
			if branchName == "main" {
				headCommit, headErr := cr.ReadHead()
				if headErr == nil && headCommit != "" && headCommit != strings.Repeat("0", 64) {
					m.logger.Printf("Repairing main branch ref with HEAD commit: %s", headCommit)
					err = cr.WriteRef(refPath, headCommit)
					if err != nil {
						m.logger.Printf("Warning: failed to repair main branch ref: %v", err)
					} else {
						branches[branchName] = headCommit
						continue
					}
				}
			}

			// Try to get the hash of the file with "git log" if we have it
			commitHashBytes, err := os.ReadFile(fullRefPath)
			if err != nil || len(commitHashBytes) == 0 {
				// Last resort: check if there are any pushes we can see in the objects dir
				m.logger.Printf("Warning: could not read branch ref %s for repo %s: %v", branchName, repoPath, err)
				continue
			}
		}

		// Normal flow: read the file content
		commitHashBytes, err := core.ReadFileContent(fullRefPath)
		if err != nil {
			m.logger.Printf("Warning: could not read branch ref %s for repo %s: %v", branchName, repoPath, err)
			continue
		}

		commitHash := strings.TrimSpace(string(commitHashBytes))
		if commitHash == "" {
			m.logger.Printf("Warning: empty commit hash for branch %s", branchName)
			continue
		}

		branches[branchName] = commitHash
	}

	// Debug logging
	m.logger.Printf("GetBranches: Found %d branches for %s: %v", len(branches), repoPath, branches)

	return branches, nil
}

// GetCommitForBranch retrieves the commit hash for a specific branch.
// repoPath is the root of the repository.
func (m *Manager) GetCommitForBranch(repoPath string, branchName string) (string, error) {
	cr := m.getCoreRepository(repoPath)
	refPath := filepath.Join(cr.RefsDir, "heads", branchName)
	if !core.FileExists(refPath) {
		return "", fmt.Errorf("branch '%s' not found", branchName)
	}
	commitHashBytes, err := core.ReadFileContent(refPath)
	if err != nil {
		return "", fmt.Errorf("failed to read branch '%s': %w", branchName, err)
	}
	return strings.TrimSpace(string(commitHashBytes)), nil
}

// CreateBranch creates a new branch pointing to a specific commit.
// repoPath is the root of the repository.
func (m *Manager) CreateBranch(repoPath string, branchName string, commitHash string) error {
	if !core.IsValidHex(commitHash) || len(commitHash) != 64 { // Assuming SHA-256 hashes from core
		return fmt.Errorf("invalid commit hash: %s", commitHash)
	}
	cr := m.getCoreRepository(repoPath)
	// core.WriteRef expects refPath relative to .vec directory
	refPath := filepath.Join("refs", "heads", branchName)
	return cr.WriteRef(refPath, commitHash) // This is core.WriteRef(repoPath, refPath, commitHash)
}

// DeleteBranch deletes a branch.
// repoPath is the root of the repository.
func (m *Manager) DeleteBranch(repoPath string, branchName string) error {
	cr := m.getCoreRepository(repoPath)
	branchFile := filepath.Join(cr.RefsDir, "heads", branchName)
	if !core.FileExists(branchFile) {
		return fmt.Errorf("branch '%s' not found for deletion", branchName)
	}
	return os.Remove(branchFile)
}

// UpdateHead updates the HEAD of the repository to point to a specific branch.
// repoPath is the root of the repository.
func (m *Manager) UpdateHead(repoPath string, branchName string) error {
	cr := m.getCoreRepository(repoPath)
	// Ensure the branch exists before pointing HEAD to it
	branchFile := filepath.Join(cr.RefsDir, "heads", branchName)
	if !core.FileExists(branchFile) {
		return fmt.Errorf("branch '%s' does not exist, cannot update HEAD", branchName)
	}
	// core.UpdateHead expects target relative to .vec dir if isRef is true
	return cr.UpdateHead(filepath.Join("refs", "heads", branchName), true)
}

// GetHeadCommitHash returns the commit hash pointed to by HEAD.
// repoPath is the root of the repository.
func (m *Manager) GetHeadCommitHash(repoPath string) (string, error) {
	cr := m.getCoreRepository(repoPath)
	return cr.ReadHead() // This is core.ReadHEAD(repoPath)
}

// SyncRepository triggers the synchronization of the repository with the database.
// It uses the configured SyncManager.
// The repoModel should have its Path field correctly set if it's used by SyncManager indirectly,
// or ownerUser and repoModel.Name are used to derive the path.
func (m *Manager) SyncRepository(repoModel *models.Repository, ownerUser *models.User) error {
	if m.syncManager == nil {
		// Log this issue, as SyncManager should have been initialized and set by the application setup.
		m.logger.Printf("Error: SyncManager not initialized in RepositoryManager for repo %s/%s. Skipping sync.", ownerUser.Username, repoModel.Name)
		// Depending on desired behavior, this could return an error or just log and skip.
		// For now, let's return an error to make it visible that setup is incomplete.
		return fmt.Errorf("SyncManager not initialized in RepositoryManager. Cannot sync repository %s/%s", ownerUser.Username, repoModel.Name)
	}

	// The repoModel.Path might not be consistently set or might be from a DB record.
	// Let SyncManager derive the canonical repoPath using ownerUser.Username and repoModel.Name.
	// It is important that SyncManager correctly resolves the path and gets a core.Repository instance.
	m.logger.Printf("Manager: Triggering sync for repository %s/%s (DB ID: %d)", ownerUser.Username, repoModel.Name, repoModel.ID)
	return m.syncManager.SynchronizeRepository(repoModel, ownerUser) // Pass models, SyncManager handles coreRepo instantiation
}
