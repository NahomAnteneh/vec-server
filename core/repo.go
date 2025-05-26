package core

import (
	"fmt"
	"path/filepath"
)

// Repository represents a Vec repository context
type Repository struct {
	Root       string
	VecDir     string
	ObjectsDir string
	RefsDir    string
	ConfigFile string
	HeadPath   string
}

// NewRepository creates a new repository context with the given root directory
func NewRepository(root string) *Repository {
	vecDir := filepath.Join(root, VecDirName)

	return &Repository{
		Root:       root,
		VecDir:     vecDir,
		ObjectsDir: filepath.Join(vecDir, "objects"),
		RefsDir:    filepath.Join(vecDir, "refs"),
		ConfigFile: filepath.Join(vecDir, "config"),
		HeadPath:   filepath.Join(vecDir, HeadFile),
	}
}

// FindRepository searches for a Vec repository from the current directory
func FindRepository() (*Repository, error) {
	root, err := GetVecRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to find repository: %w", err)
	}

	return NewRepository(root), nil
}

// CreateRepo initializes a new Vec repository using Repository context
func CreateRepo(repo *Repository) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	if FileExists(repo.VecDir) {
		return fmt.Errorf("vec repository already initialized at %s", repo.Root)
	}

	if err := EnsureDirExists(repo.VecDir); err != nil {
		return FSError(fmt.Sprintf("failed to create .vec directory at %s", repo.VecDir), err)
	}

	if err := CreateCommonDirectories(repo); err != nil {
		return fmt.Errorf("failed to create common directories: %w", err)
	}

	fmt.Printf("Initialized empty Vec repository in %s\n", repo.VecDir)
	return nil
}

// CreateBareRepo creates a bare repository using Repository context
func CreateBareRepo(repo *Repository) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	dir := repo.Root

	if FileExists(dir) {
		entries, err := ReadDir(dir)
		if err != nil {
			return FSError(fmt.Sprintf("failed to read directory %s", dir), err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("directory %s is not empty", dir)
		}
	} else {
		if err := EnsureDirExists(dir); err != nil {
			return FSError(fmt.Sprintf("failed to create directory %s", dir), err)
		}
	}

	if err := CreateCommonDirectories(repo); err != nil {
		return fmt.Errorf("failed to create common directories: %w", err)
	}

	configFile := filepath.Join(dir, "config")
	config := "[core]\n\tbare = true\n"
	if err := WriteFileContent(configFile, []byte(config), 0644); err != nil {
		return FSError("failed to create config file", err)
	}

	fmt.Printf("Initialized empty bare Vec repository in %s\n", dir)
	return nil
}

// ReadHead retrieves the current HEAD commit hash
func (r *Repository) ReadHead() (string, error) {
	return ReadHEAD(r)
}

// GetCurrentBranch returns the name of the current branch
func (r *Repository) GetCurrentBranch() (string, error) {
	return GetCurrentBranch(r)
}

// WriteObject writes an object to the repository
func (r *Repository) WriteObject(objectType string, data []byte) (string, error) {
	return WriteObject(r, objectType, data)
}

// ReadObject reads an object from the repository
func (r *Repository) ReadObject(hash string) (string, []byte, error) {
	return ReadObject(r, hash)
}

// UpdateHead updates the HEAD reference
func (r *Repository) UpdateHead(target string, isRef bool) error {
	return UpdateHEAD(r, target, isRef)
}

// GetConfig reads a configuration value
func (r *Repository) GetConfig(key string) (string, error) {
	return GetConfigValue(r, key)
}

// SetConfig writes a configuration value
func (r *Repository) SetConfig(key, value string, global bool) error {
	scope := ScopeLocal
	if global {
		scope = ScopeGlobal
	}
	return SetConfigValue(r, key, value, scope)
}

// UnsetConfig removes a configuration value
func (r *Repository) UnsetConfig(key string, global bool) error {
	scope := ScopeLocal
	if global {
		scope = ScopeGlobal
	}
	return UnsetConfigValue(r, key, "", scope)
}

// GetAllBranches returns a list of all branches in the repository
func (r *Repository) GetAllBranches() ([]string, error) {
	return GetAllBranches(r)
}

// SetBranchUpstream sets the upstream branch for a local branch
func (r *Repository) SetBranchUpstream(branchName, remoteName string) error {
	return SetBranchUpstream(r, branchName, remoteName)
}

// IsPathIgnored checks if a given path should be ignored
func (r *Repository) IsPathIgnored(path string) (bool, error) {
	return IsIgnored(r.Root, path)
}

// HashFile calculates the SHA-256 hash of a file
func (r *Repository) HashFile(path string) (string, error) {
	return HashFile(path)
}

// WriteRef writes a reference file
func (r *Repository) WriteRef(refPath, commitHash string) error {
	return WriteRef(r, refPath, commitHash)
}
