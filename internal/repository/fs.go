package repository

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidPath is returned when a path is invalid or potentially unsafe
	ErrInvalidPath = errors.New("invalid path")

	// ErrFileExists is returned when attempting to create a file that already exists
	ErrFileExists = errors.New("file already exists")

	// fileLocks provides mutex locks for individual files to prevent concurrent access
	fileLocks = &sync.Map{}
)

// FS handles filesystem operations for repositories
type FS struct{}

// NewFS creates a new filesystem handler
func NewFS() *FS {
	return &FS{}
}

// LockFile acquires a lock for a specific file
func (fs *FS) LockFile(path string) func() {
	value, _ := fileLocks.LoadOrStore(path, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return func() { mutex.Unlock() }
}

// ValidatePath checks if a path is valid and safe
func (fs *FS) ValidatePath(basePath, path string) error {
	// Normalize paths
	cleanBase := filepath.Clean(basePath)
	cleanPath := filepath.Clean(filepath.Join(cleanBase, path))

	// Check if the path is within the base path
	if !strings.HasPrefix(cleanPath, cleanBase) || cleanPath == cleanBase {
		return ErrInvalidPath
	}

	return nil
}

// CreateDirectory creates a directory and all necessary parent directories
func (fs *FS) CreateDirectory(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// CreateFile creates a new file with the given content
func (fs *FS) CreateFile(path string, data []byte, perm os.FileMode) error {
	unlock := fs.LockFile(path)
	defer unlock()

	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		return ErrFileExists
	}

	// Create parent directories if they don't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, perm)
}

// AtomicWriteFile atomically writes data to a file using a temporary file
func (fs *FS) AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	unlock := fs.LockFile(path)
	defer unlock()

	// Create parent directories if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create temporary file
	tmpPath := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		os.Remove(tmpPath) // Clean up on error
		return err
	}

	// Rename the temporary file to the target file (atomic operation)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // Clean up on error
		return err
	}

	return nil
}

// ReadFile reads the content of a file
func (fs *FS) ReadFile(path string) ([]byte, error) {
	unlock := fs.LockFile(path)
	defer unlock()

	return os.ReadFile(path)
}

// DeleteFile removes a file
func (fs *FS) DeleteFile(path string) error {
	unlock := fs.LockFile(path)
	defer unlock()

	return os.Remove(path)
}

// DeleteDirectory recursively deletes a directory and its contents
func (fs *FS) DeleteDirectory(path string) error {
	return os.RemoveAll(path)
}

// CopyFile copies a file from src to dst
func (fs *FS) CopyFile(src, dst string) error {
	// Lock both source and destination files
	unlockSrc := fs.LockFile(src)
	defer unlockSrc()
	unlockDst := fs.LockFile(dst)
	defer unlockDst()

	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy content
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	// Copy permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode())
}
