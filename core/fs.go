package core

import (
	"bytes"
	"compress/zlib"
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

// FileExists checks if a file or directory exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// ReadFileContent reads the content of a file.
func ReadFileContent(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, FSError(fmt.Sprintf("failed to read file %s", filePath), err)
	}
	return content, nil
}

// EnsureDirExists creates a directory if it doesn't exist.
func EnsureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return FSError(fmt.Sprintf("failed to create directory %s", path), err)
		}
	} else if err != nil {
		return FSError(fmt.Sprintf("failed to stat directory %s", path), err)
	}
	return nil
}

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return FSError(fmt.Sprintf("failed to open source file %s", src), err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return FSError(fmt.Sprintf("failed to create destination file %s", dst), err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return FSError(fmt.Sprintf("failed to copy file content from %s to %s", src, dst), err)
	}

	return nil
}

// GetVecRoot returns the root directory of the Vec repository.
func GetVecRoot() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", FSError("failed to get current directory", err)
	}

	startDir := currentDir
	if forcedRoot := os.Getenv("VEC_REPOSITORY_PATH"); forcedRoot != "" {
		vecDir := filepath.Join(forcedRoot, VecDirName)
		if FileExists(vecDir) {
			return forcedRoot, nil
		}
		return "", RepositoryError(fmt.Sprintf("VEC_REPOSITORY_PATH is set to '%s' but no repository found there", forcedRoot), nil)
	}

	for {
		vecDir := filepath.Join(currentDir, VecDirName)
		if FileExists(vecDir) {
			return currentDir, nil
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			errMsg := fmt.Sprintf("not a vec repository (or any of the parent directories starting from: %s)", startDir)
			return "", RepositoryError(errMsg, ErrNotARepository)
		}
		currentDir = parentDir
	}
}

// IsIgnored checks if a given path should be ignored by Vec.
func IsIgnored(repoRoot, path string) (bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, FSError("failed to get absolute path", err)
	}

	absRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return false, FSError("failed to get absolute repo root path", err)
	}

	relPath, err := filepath.Rel(absRepoRoot, absPath)
	if err != nil {
		return false, FSError("failed to get relative path", err)
	}

	if strings.HasPrefix(relPath, VecDirName) {
		return true, nil
	}

	ignorePatternCacheMutex.RLock()
	patterns, ok := ignorePatternCache[absRepoRoot]
	ignorePatternCacheMutex.RUnlock()

	if !ok {
		patterns = LoadIgnorePatterns(absRepoRoot)
	}

	return MatchIgnorePatterns(patterns, relPath), nil
}

// WriteFileContent writes content to a file with the specified permissions.
func WriteFileContent(filePath string, content []byte, perm os.FileMode) error {
	// Ensure the directory exists
	if err := EnsureDirExists(filepath.Dir(filePath)); err != nil {
		return FSError(fmt.Sprintf("failed to create directory for %s", filePath), err)
	}

	// Make sure to create the file and properly flush/sync content
	f, err := os.Create(filePath)
	if err != nil {
		return FSError(fmt.Sprintf("failed to create file %s", filePath), err)
	}

	// Use defer with a named return value to handle file closing properly
	defer func() {
		closeErr := f.Close()
		if err == nil && closeErr != nil {
			err = FSError(fmt.Sprintf("failed to close file %s", filePath), closeErr)
		}
	}()

	// Write the content
	if _, err := f.Write(content); err != nil {
		return FSError(fmt.Sprintf("failed to write content to file %s", filePath), err)
	}

	// Ensure content is flushed to disk
	if err := f.Sync(); err != nil {
		return FSError(fmt.Sprintf("failed to sync file %s", filePath), err)
	}

	// Set permissions
	if err := f.Chmod(perm); err != nil {
		return FSError(fmt.Sprintf("failed to set permissions on file %s", filePath), err)
	}

	return nil
}

// CreateFile creates a new file with the specified content and permissions.
func CreateFile(filePath string, content []byte, perm os.FileMode) error {
	if err := EnsureDirExists(filepath.Dir(filePath)); err != nil {
		return FSError(fmt.Sprintf("failed to create parent directory for %s", filePath), err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return FSError(fmt.Sprintf("failed to create file %s", filePath), err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return FSError(fmt.Sprintf("failed to write content to file %s", filePath), err)
	}

	if err := file.Chmod(perm); err != nil {
		return FSError(fmt.Sprintf("failed to set permissions on file %s", filePath), err)
	}

	return nil
}

// OpenFile opens a file for reading.
func OpenFile(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, FSError(fmt.Sprintf("failed to open file %s", filePath), err)
	}
	return file, nil
}

// StatFile returns file information.
func StatFile(filePath string) (os.FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, FSError(fmt.Sprintf("failed to stat file %s", filePath), err)
	}
	return info, nil
}

// IsNotExist checks if an error indicates a file does not exist.
func IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// RemoveFile removes a file or directory.
func RemoveFile(filePath string) error {
	if err := os.Remove(filePath); err != nil {
		return FSError(fmt.Sprintf("failed to remove file %s", filePath), err)
	}
	return nil
}

// RemoveAll removes a directory and all its contents.
func RemoveAll(dirPath string) error {
	if err := os.RemoveAll(dirPath); err != nil {
		return FSError(fmt.Sprintf("failed to remove directory %s", dirPath), err)
	}
	return nil
}

// RenameFile renames (moves) a file or directory.
func RenameFile(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return FSError(fmt.Sprintf("failed to rename %s to %s", oldPath, newPath), err)
	}
	return nil
}

// ReadDir reads the directory and returns a list of directory entries.
func ReadDir(dirPath string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, FSError(fmt.Sprintf("failed to read directory %s", dirPath), err)
	}
	return entries, nil
}

// WalkDir walks the file tree rooted at the given directory.
func WalkDir(root string, fn filepath.WalkFunc) error {
	return filepath.Walk(root, fn)
}

// CreateTemp creates a temporary file.
func CreateTemp(dir, pattern string) (*os.File, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, FSError("failed to create temporary file", err)
	}
	return file, nil
}

// GetUserHomeDir returns the user's home directory.
func GetUserHomeDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", FSError("failed to get user home directory", err)
	}
	return homeDir, nil
}

// GetTempDir returns the system temporary directory.
func GetTempDir() string {
	return os.TempDir()
}

// Chmod changes the file mode of the named file.
func Chmod(name string, mode os.FileMode) error {
	if err := os.Chmod(name, mode); err != nil {
		return FSError(fmt.Sprintf("failed to change file mode of %s", name), err)
	}
	return nil
}

// LoadIgnorePatterns loads and caches patterns from .vecignore file.
func LoadIgnorePatterns(absRepoRoot string) []string {
	vecignorePath := filepath.Join(absRepoRoot, ".vecignore")
	patterns := []string{}

	if FileExists(vecignorePath) {
		vecignoreContent, err := ReadFileContent(vecignorePath)
		if err == nil {
			rawPatterns := strings.Split(string(vecignoreContent), "\n")
			patterns = make([]string, 0, len(rawPatterns))

			for _, pattern := range rawPatterns {
				pattern = strings.TrimSpace(pattern)
				if pattern == "" || strings.HasPrefix(pattern, "#") {
					continue
				}

				if _, err := filepath.Match(pattern, "test-filename"); err != nil {
					fmt.Fprintf(os.Stderr, "warning: invalid pattern in .vecignore: %s\n", pattern)
					continue
				}

				patterns = append(patterns, filepath.Clean(pattern))
			}
		}
	}

	ignorePatternCacheMutex.Lock()
	ignorePatternCache[absRepoRoot] = patterns
	ignorePatternCacheMutex.Unlock()

	return patterns
}

// MatchIgnorePatterns checks if a path matches any ignore patterns.
func MatchIgnorePatterns(patterns []string, relPath string) bool {
	relPath = filepath.Clean(relPath)
	baseName := filepath.Base(relPath)

	var relPathParts []string
	if relPath != "" && relPath != "." && relPath != string(filepath.Separator) {
		relPathParts = strings.Split(relPath, string(filepath.Separator))
	}

	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}

		if !strings.ContainsRune(pattern, '/') && !strings.ContainsRune(pattern, '\\') {
			if m, _ := filepath.Match(pattern, baseName); m {
				return true
			}
		}

		if len(relPathParts) > 0 {
			for i := range relPathParts {
				partialPath := filepath.Join(relPathParts[:i+1]...)
				if m, _ := filepath.Match(pattern, partialPath); m {
					return true
				}
			}
		}
	}

	return false
}

// CreateCommonDirectories creates the standard directory structure for a Vec repository.
func CreateCommonDirectories(repo *Repository) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	baseDir := repo.VecDir

	subDirs := []string{
		filepath.Join(baseDir, "objects"),
		filepath.Join(baseDir, "objects", "pack"),
		filepath.Join(baseDir, "objects", "info"),
		filepath.Join(baseDir, "refs", "heads"),
		filepath.Join(baseDir, "refs", "remotes"),
		filepath.Join(baseDir, "logs", "refs", "heads"),
		filepath.Join(baseDir, "logs"),
		filepath.Join(baseDir, "config"),
	}

	for _, subDir := range subDirs {
		if err := EnsureDirExists(subDir); err != nil {
			return FSError(fmt.Sprintf("failed to create subdirectory %s", subDir), err)
		}
	}

	files := map[string]string{
		filepath.Join(baseDir, "objects", "info", "packs"):      "",
		filepath.Join(baseDir, "objects", "info", "alternates"): "",
		filepath.Join(baseDir, "HEAD"):                          "ref: refs/heads/main\n",
		filepath.Join(baseDir, "logs", "HEAD"):                  "",
		filepath.Join(baseDir, "refs", "heads", "main"):         "",
	}

	for file, content := range files {
		if err := CreateFile(file, []byte(content), 0644); err != nil {
			return FSError(fmt.Sprintf("failed to create file %s", file), err)
		}
	}

	return nil
}

// GetObjectPath returns the path where an object should be stored.
func GetObjectPath(repo *Repository, hash string) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}
	if len(hash) != 64 || !IsValidHex(hash) {
		return "", ObjectError("invalid object hash", nil)
	}
	objectsDir := repo.ObjectsDir
	prefix := hash[:2]
	suffix := hash[2:]
	return filepath.Join(objectsDir, prefix, suffix), nil
}

// WriteObject writes an object to the object store with zlib compression.
func WriteObject(repo *Repository, objectType string, data []byte) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}
	hash := HashBytes(objectType, data)
	objectPath, err := GetObjectPath(repo, hash)
	if err != nil {
		return "", err
	}

	if FileExists(objectPath) {
		return hash, nil
	}

	if err := EnsureDirExists(filepath.Dir(objectPath)); err != nil {
		return "", FSError("failed to create object directory", err)
	}

	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.DefaultCompression)
	if err != nil {
		return "", FSError("failed to create zlib writer", err)
	}
	header := fmt.Sprintf("%s %d\x00", objectType, len(data))
	if _, err := zw.Write([]byte(header)); err != nil {
		zw.Close()
		return "", FSError("failed to write object header", err)
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return "", FSError("failed to write object data", err)
	}
	if err := zw.Close(); err != nil {
		return "", FSError("failed to close zlib writer", err)
	}

	if err := WriteFileContent(objectPath, buf.Bytes(), 0444); err != nil {
		return "", FSError("failed to write object", err)
	}

	return hash, nil
}

// ReadObject reads and decompresses an object from the object store.
func ReadObject(repo *Repository, hash string) (string, []byte, error) {
	if repo == nil {
		return "", nil, RepositoryError("nil repository", nil)
	}
	if len(hash) != 64 || !IsValidHex(hash) {
		return "", nil, ObjectError(fmt.Sprintf("invalid object hash: %s", hash), nil)
	}

	objectPath, err := GetObjectPath(repo, hash)
	if err != nil {
		return "", nil, err
	}

	file, err := OpenFile(objectPath)
	if err != nil {
		return "", nil, FSError(fmt.Sprintf("failed to read object %s", hash), err)
	}
	defer file.Close()

	zr, err := zlib.NewReader(file)
	if err != nil {
		return "", nil, FSError(fmt.Sprintf("failed to create zlib reader for %s", hash), err)
	}
	defer zr.Close()

	content, err := io.ReadAll(zr)
	if err != nil {
		return "", nil, FSError(fmt.Sprintf("failed to read object %s", hash), err)
	}

	headerEnd := bytes.IndexByte(content, '\x00')
	if headerEnd == -1 {
		return "", nil, ObjectError("invalid object format: header not found", nil)
	}

	header := string(content[:headerEnd])
	var objectType string
	var size int
	_, err = fmt.Sscanf(header, "%s %d", &objectType, &size)
	if err != nil {
		return "", nil, ObjectError("invalid object header", err)
	}

	data := content[headerEnd+1:]
	if len(data) != size {
		return "", nil, ObjectError(fmt.Sprintf("object size mismatch: expected %d, got %d", size, len(data)), nil)
	}

	return objectType, data, nil
}
