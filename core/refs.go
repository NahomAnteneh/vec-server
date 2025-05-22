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
func ReadHEADFile(repoRoot string) (string, error) {
	headPath := filepath.Join(repoRoot, VecDirName, HeadFile)
	headContent, err := ReadFileContent(headPath)
	if err != nil {
		return "", RefError("failed to read HEAD", err)
	}
	return strings.TrimSpace(string(headContent)), nil
}

// ReadHEAD retrieves the commit ID that HEAD points to.
func ReadHEAD(repoRoot string) (string, error) {
	headContent, err := ReadHEADFile(repoRoot)
	if err != nil {
		return "", err // Already a RefError or similar
	}

	// Check if HEAD is a ref
	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimPrefix(headContent, "ref: ")
		refFile := filepath.Join(repoRoot, VecDirName, refPath)

		// Check if reference file exists
		if !FileExists(refFile) {
			// If the ref file (e.g., refs/heads/main) doesn't exist, it's an error.
			// This could mean a broken ref or an uninitialized branch.
			return "", NotFoundError(ErrCategoryRef, fmt.Sprintf("reference file '%s' pointed to by HEAD", refPath))
		}

		commitID, err := ReadFileContent(refFile)
		if err != nil {
			return "", RefError(fmt.Sprintf("failed to read reference file '%s'", refPath), err)
		}
		return strings.TrimSpace(string(commitID)), nil
	}

	// Handle detached HEAD (direct commit hash)
	if len(headContent) == 64 && IsValidHex(headContent) {
		return headContent, nil
	}

	// If not a valid ref and not a valid hash, it's an invalid HEAD content.
	return "", RefError(fmt.Sprintf("invalid HEAD content: '%s'", headContent), nil)
}

// GetHeadCommit gets the SHA-256 of the current HEAD commit.
// This is an alias for ReadHEAD for backward compatibility.
func GetHeadCommit(repoRoot string) (string, error) {
	return ReadHEAD(repoRoot)
}

// GetCurrentBranch returns the name of the current branch.
func GetCurrentBranch(repoRoot string) (string, error) {
	headContent, err := ReadHEADFile(repoRoot)
	if err != nil {
		return "", err
	}

	// Check if HEAD is a ref
	if strings.HasPrefix(headContent, "ref: ") {
		refPath := strings.TrimPrefix(headContent, "ref: ")
		parts := strings.Split(refPath, "/")
		branchName := parts[len(parts)-1] // Get the last part
		return branchName, nil
	}

	// Detached HEAD
	return "(HEAD detached)", nil
}

// WriteRef writes a reference file.
func WriteRef(repoRoot, refPath, commitHash string) error {
	fullPath := filepath.Join(repoRoot, VecDirName, refPath)

	// Ensure the directory exists
	if err := EnsureDirExists(filepath.Dir(fullPath)); err != nil {
		return RefError("failed to create reference directory", err)
	}

	// Write the reference file
	if err := os.WriteFile(fullPath, []byte(commitHash), 0644); err != nil {
		return RefError("failed to write reference file", err)
	}

	return nil
}

// UpdateHEAD updates the HEAD file to point to a reference or commit hash.
func UpdateHEAD(repoRoot, target string, isRef bool) error {
	headPath := filepath.Join(repoRoot, VecDirName, HeadFile)
	var content string

	if isRef {
		content = fmt.Sprintf("ref: %s", target)
	} else {
		content = target
	}

	if err := os.WriteFile(headPath, []byte(content), 0644); err != nil {
		return RefError("failed to update HEAD", err)
	}

	return nil
}

// GetAllBranches returns a list of all branches in the repository
func GetAllBranches(repoRoot string) ([]string, error) {
	branchesDir := filepath.Join(repoRoot, VecDirName, "refs", "heads")
	if !FileExists(branchesDir) {
		return nil, NotFoundError(ErrCategoryRef, "branches directory")
	}

	var branches []string
	err := filepath.Walk(branchesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip directories, we only want the branch files
		if !info.IsDir() {
			// Get the branch name from the path
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
func SetBranchUpstream(repoRoot, branchName, remoteName string) error {
	// Ensure the branch exists
	branchPath := filepath.Join(repoRoot, VecDirName, "refs", "heads", branchName)
	if !FileExists(branchPath) {
		return NotFoundError(ErrCategoryRef, fmt.Sprintf("branch '%s'", branchName))
	}

	// Set upstream configuration in the config file
	branchKey := fmt.Sprintf("branch.%s.remote", branchName)
	mergeKey := fmt.Sprintf("branch.%s.merge", branchName)

	// Read the config
	configPath := filepath.Join(repoRoot, VecDirName, "config")
	config, err := ReadConfig(configPath)
	if err != nil {
		return ConfigError("failed to read config", err)
	}

	// Update the config
	config[branchKey] = remoteName
	config[mergeKey] = fmt.Sprintf("refs/heads/%s", branchName)

	// Write the updated config
	return WriteConfig(configPath, config)
}
