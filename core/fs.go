package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Common constants
const (
	VecDirName = ".vec"
)

// Global cache for ignore patterns to avoid reloading and reparsing .vecignore
var (
	ignorePatternCache      = make(map[string][]string)
	ignorePatternCacheMutex sync.RWMutex
)

// FileExists checks if a file exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// ReadFileContent reads the content of a file.
func ReadFileContent(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return content, nil
}

// EnsureDirExists creates a directory if it doesn't exist.
func EnsureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat directory %s: %w", path, err)
	}
	return nil
}

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	return nil
}

// GetVecRoot returns the root directory of the Vec repository.
// It searches for the .vec directory in the current and parent directories.
func GetVecRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	// Store the original starting point to help with error message
	startDir := currentDir

	// Check for environment variable to force a specific repository path
	if forcedRoot := os.Getenv("VEC_REPOSITORY_PATH"); forcedRoot != "" {
		vecDir := filepath.Join(forcedRoot, VecDirName)
		if FileExists(vecDir) {
			return forcedRoot, nil
		}
		return "", fmt.Errorf("VEC_REPOSITORY_PATH is set to '%s' but no repository found there", forcedRoot)
	}

	// Search up the directory tree for a .vec directory
	for {
		vecDir := filepath.Join(currentDir, VecDirName)
		if FileExists(vecDir) {
			return currentDir, nil
		}

		// Move to the parent directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir { // Reached root
			errMsg := fmt.Sprintf("not a vec repository (or any of the parent directories starting from: %s)", startDir)
			return "", RepositoryError(errMsg, ErrNotARepository)
		}
		currentDir = parentDir
	}
}

// IsIgnored checks if a given path should be ignored by Vec.
func IsIgnored(repoRoot, path string) (bool, error) {
	// First ensure we're working with absolute paths
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path: %w", err)
	}

	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute repo root path: %w", err)
	}

	// Get path relative to repository root
	relPath, err := filepath.Rel(absRepoRoot, absPath)
	if err != nil {
		return false, fmt.Errorf("failed to get relative path: %w", err)
	}

	// Ignore .vec directory and its contents
	if strings.HasPrefix(relPath, VecDirName) {
		return true, nil
	}

	// Check for cached patterns first
	ignorePatternCacheMutex.RLock()
	patterns, ok := ignorePatternCache[absRepoRoot]
	ignorePatternCacheMutex.RUnlock()

	// If not in cache, load patterns from .vecignore
	if !ok {
		patterns = LoadIgnorePatterns(absRepoRoot)
	}

	// Match against patterns
	return MatchIgnorePatterns(patterns, relPath), nil
}

// LoadIgnorePatterns loads and caches patterns from .vecignore file
func LoadIgnorePatterns(absRepoRoot string) []string {
	vecignorePath := filepath.Join(absRepoRoot, ".vecignore")
	patterns := []string{}

	if FileExists(vecignorePath) {
		vecignoreContent, err := ReadFileContent(vecignorePath)
		if err == nil {
			// Parse valid patterns
			rawPatterns := strings.Split(string(vecignoreContent), "\n")
			patterns = make([]string, 0, len(rawPatterns))

			for _, pattern := range rawPatterns {
				pattern = strings.TrimSpace(pattern)
				if pattern == "" || strings.HasPrefix(pattern, "#") {
					continue // Skip empty lines and comments
				}

				// Validate pattern before adding to cache
				if _, err := filepath.Match(pattern, "test-filename"); err != nil {
					// Log invalid pattern but don't fail
					fmt.Fprintf(os.Stderr, "warning: invalid pattern in .vecignore: %s\n", pattern)
					continue
				}

				patterns = append(patterns, filepath.Clean(pattern))
			}
		}
	}

	// Cache the parsed patterns
	ignorePatternCacheMutex.Lock()
	ignorePatternCache[absRepoRoot] = patterns
	ignorePatternCacheMutex.Unlock()

	return patterns
}

// MatchIgnorePatterns checks if a path matches any ignore patterns
func MatchIgnorePatterns(patterns []string, relPath string) bool {
	relPath = filepath.Clean(relPath) // Ensure OS-specific separators for matching
	baseName := filepath.Base(relPath)

	// Pre-calculate path components for the directory prefix check.
	// Ensure relPathParts are not empty if relPath is "." or empty.
	var relPathParts []string
	if relPath != "" && relPath != "." && relPath != string(filepath.Separator) {
		relPathParts = strings.Split(relPath, string(filepath.Separator))
	}

	for _, pattern := range patterns {
		// 1. Direct match against the full relative path
		// (e.g., pattern "foo/bar.txt", relPath "foo/bar.txt")
		// (e.g., pattern "*.txt", relPath "file.txt")
		matched, _ := filepath.Match(pattern, relPath) // Error already checked during parsing
		if matched {
			return true
		}

		// 2. If pattern does not contain a path separator, try matching against the basename.
		// (e.g., pattern "*.log" to match "some/dir/file.log")
		if !strings.ContainsRune(pattern, '/') && !strings.ContainsRune(pattern, '\\') {
			if m, _ := filepath.Match(pattern, baseName); m {
				return true
			}
		}

		// 3. Check if pattern matches any parent directory/prefix of relPath.
		// (e.g., pattern "build" to ignore "build/output/file.txt")
		// This is the original loop for prefix matching.
		if len(relPathParts) > 0 {
			for i := range relPathParts {
				// Construct prefix path, e.g., "part1", then "part1/part2"
				// Avoid matching the full path again if it was already checked by rule #1,
				// though repeated check is harmless.
				partialPath := filepath.Join(relPathParts[:i+1]...)
				if m, _ := filepath.Match(pattern, partialPath); m {
					return true
				}
			}
		}
	}

	return false
}
