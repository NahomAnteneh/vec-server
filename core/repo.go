package core

import (
	"path/filepath"
)

// Repository represents a Vec repository context
type Repository struct {
	// Root directory of the repository
	Root string

	// Common paths
	VecDir     string
	ObjectsDir string
	RefsDir    string
	ConfigFile string
	HeadPath   string
}

// NewRepository creates a new repository context
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
		return nil, err
	}

	return NewRepository(root), nil
}

// ReadHead retrieves the current HEAD commit hash
func (r *Repository) ReadHead() (string, error) {
	return ReadHEAD(r.Root)
}

// GetCurrentBranch returns the name of the current branch
func (r *Repository) GetCurrentBranch() (string, error) {
	return GetCurrentBranch(r.Root)
}

// WriteObject writes an object to the repository
func (r *Repository) WriteObject(objectType string, data []byte) (string, error) {
	return WriteObject(r.Root, objectType, data)
}

// ReadObject reads an object from the repository
func (r *Repository) ReadObject(hash string) (string, []byte, error) {
	return ReadObject(r.Root, hash)
}

// UpdateHead updates the HEAD reference
func (r *Repository) UpdateHead(target string, isRef bool) error {
	return UpdateHEAD(r.Root, target, isRef)
}

// GetConfig reads a configuration value
func (r *Repository) GetConfig(key string) (string, error) {
	return GetConfigValue(r.Root, key)
}

// SetConfig writes a configuration value
func (r *Repository) SetConfig(key, value string, global bool) error {
	return SetConfigValue(r.Root, key, value, global)
}

// UnsetConfig removes a configuration value
func (r *Repository) UnsetConfig(key string, global bool) error {
	return UnsetConfigValue(r.Root, key, global)
}

// GetAllBranches returns a list of all branches in the repository
func (r *Repository) GetAllBranches() ([]string, error) {
	return GetAllBranches(r.Root)
}

// SetBranchUpstream sets the upstream branch for a local branch
func (r *Repository) SetBranchUpstream(branchName, remoteName string) error {
	return SetBranchUpstream(r.Root, branchName, remoteName)
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
	return WriteRef(r.Root, refPath, commitHash)
}
