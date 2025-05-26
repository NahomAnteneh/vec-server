package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HeadFile = "HEAD"
)

// ReadHEADFile reads the content of the HEAD file and returns it trimmed.
func ReadHEADFile(repo *Repository) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}
	headPath := repo.HeadPath
	headContent, err := ReadFileContent(headPath)
	if err != nil {
		return "", RefError("failed to read HEAD", err)
	}
	return strings.TrimSpace(string(headContent)), nil
}

// ReadHEAD retrieves the commit ID that HEAD points to.
func ReadHEAD(repo *Repository) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}
	headContent, err := ReadHEADFile(repo)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimPrefix(headContent, "ref: ")
		refFile := filepath.Join(repo.VecDir, refPath)

		if !FileExists(refFile) {
			return "", NotFoundError(ErrCategoryRef, fmt.Sprintf("reference file '%s' pointed to by HEAD", refPath))
		}

		commitID, err := ReadFileContent(refFile)
		if err != nil {
			return "", RefError(fmt.Sprintf("failed to read reference file '%s'", refPath), err)
		}
		return strings.TrimSpace(string(commitID)), nil
	}

	if len(headContent) == 64 && IsValidHex(headContent) {
		return headContent, nil
	}

	return "", RefError(fmt.Sprintf("invalid HEAD content: '%s'", headContent), nil)
}

// GetHeadCommit gets the SHA-256 of the current HEAD commit.
func GetHeadCommit(repo *Repository) (string, error) {
	return ReadHEAD(repo)
}

// GetCurrentBranch returns the name of the current branch.
func GetCurrentBranch(repo *Repository) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}
	headContent, err := ReadHEADFile(repo)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimPrefix(headContent, "ref: ")
		parts := strings.Split(refPath, "/")
		branchName := parts[len(parts)-1]
		return branchName, nil
	}

	return "(HEAD detached)", nil
}

// ReadRef reads the commit ID from a reference file (e.g., refs/heads/main).
func ReadRef(repo *Repository, refPath string) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}

	// Construct the full path to the ref file
	absPath := filepath.Join(repo.VecDir, refPath)

	// Read the ref file
	content, err := os.ReadFile(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", RefError(fmt.Sprintf("reference %s does not exist", refPath), err)
		}
		return "", RefError(fmt.Sprintf("failed to read reference %s", refPath), err)
	}

	// Trim whitespace and validate
	commitID := strings.TrimSpace(string(content))
	if commitID == "" {
		return "", RefError(fmt.Sprintf("reference %s is empty", refPath), nil)
	}

	// Basic validation of commit ID (SHA-256 hash)
	if len(commitID) != 64 || !IsValidHex(commitID) {
		return "", RefError(fmt.Sprintf("invalid commit ID in reference %s", refPath), nil)
	}

	return commitID, nil
}

// WriteRef writes a reference file.
func WriteRef(repo *Repository, refPath, commitHash string) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	fullPath := filepath.Join(repo.VecDir, refPath)

	if err := EnsureDirExists(filepath.Dir(fullPath)); err != nil {
		return RefError("failed to create reference directory", err)
	}

	if err := WriteFileContent(fullPath, []byte(commitHash), 0644); err != nil {
		return RefError("failed to write reference file", err)
	}

	return nil
}

// UpdateHEAD updates the HEAD file to point to a reference or commit hash.
func UpdateHEAD(repo *Repository, target string, isRef bool) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	var content string
	if isRef {
		content = fmt.Sprintf("ref: %s", target)
	} else {
		content = target
	}

	if err := WriteFileContent(repo.HeadPath, []byte(content), 0644); err != nil {
		return RefError("failed to update HEAD", err)
	}

	return nil
}

// GetAllBranches returns a list of all branches in the repository
func GetAllBranches(repo *Repository) ([]string, error) {
	if repo == nil {
		return nil, RepositoryError("nil repository", nil)
	}
	branchesDir := repo.RefsDir + "/heads"
	if !FileExists(branchesDir) {
		return nil, NotFoundError(ErrCategoryRef, "branches directory")
	}

	var branches []string
	err := WalkDir(branchesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relativePath, err := filepath.Rel(branchesDir, path)
			if err != nil {
				return err
			}
			branches = append(branches, relativePath)
		}
		return nil
	})

	if err != nil {
		return nil, RefError("failed to list branches", err)
	}

	return branches, nil
}

// SetBranchUpstream sets the upstream branch for a local branch
func SetBranchUpstream(repo *Repository, branchName, remoteName string) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	branchPath := filepath.Join(repo.RefsDir, "heads", branchName)
	if !FileExists(branchPath) {
		return NotFoundError(ErrCategoryRef, fmt.Sprintf("branch '%s'", branchName))
	}

	branchKey := fmt.Sprintf("branch.%s.remote", branchName)
	mergeKey := fmt.Sprintf("branch.%s.merge", branchName)

	configPath := repo.ConfigFile
	config, err := ReadConfig(configPath)
	if err != nil {
		return ConfigError("failed to read config", err)
	}

	config[branchKey] = remoteName
	config[mergeKey] = fmt.Sprintf("refs/heads/%s", branchName)

	return WriteConfig(configPath, config)
}
