package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// HashFile calculates the SHA-256 hash of a file, including the Vec object header.
func HashFile(filePath string) (string, error) {
	content, err := ReadFileContent(filePath)
	if err != nil {
		return "", err
	}
	return HashBytes("blob", content), nil
}

// HashBytes calculates the SHA-256 hash of the given data, including the Vec object header.
func HashBytes(objectType string, data []byte) string {
	header := fmt.Sprintf("%s %d\x00", objectType, len(data))
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// IsValidHex checks if a string is a valid hexadecimal value.
func IsValidHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// GetObjectPath returns the path where an object should be stored.
func GetObjectPath(repoRoot, hash string) string {
	objectsDir := filepath.Join(repoRoot, VecDirName, "objects")
	prefix := hash[:2]
	suffix := hash[2:]
	return filepath.Join(objectsDir, prefix, suffix)
}

// WriteObject writes an object to the object store.
func WriteObject(repoRoot, objectType string, data []byte) (string, error) {
	// Calculate hash
	hash := HashBytes(objectType, data)

	// Determine object path
	objectPath := GetObjectPath(repoRoot, hash)

	// Create directory structure if it doesn't exist
	objectDir := filepath.Dir(objectPath)
	if err := EnsureDirExists(objectDir); err != nil {
		return "", fmt.Errorf("failed to create object directory: %w", err)
	}

	// Don't overwrite existing objects (idempotent operation)
	if FileExists(objectPath) {
		return hash, nil
	}

	// Write object
	header := fmt.Sprintf("%s %d\x00", objectType, len(data))
	content := append([]byte(header), data...)

	if err := os.WriteFile(objectPath, content, 0444); err != nil {
		return "", fmt.Errorf("failed to write object: %w", err)
	}

	return hash, nil
}

// ReadObject reads an object from the object store.
func ReadObject(repoRoot, hash string) (string, []byte, error) {
	// Verify hash format
	if len(hash) != 64 || !IsValidHex(hash) {
		return "", nil, fmt.Errorf("invalid object hash: %s", hash)
	}

	// Get object path
	objectPath := GetObjectPath(repoRoot, hash)

	// Read object
	content, err := ReadFileContent(objectPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read object %s: %w", hash, err)
	}

	// Parse header
	headerEnd := -1
	for i := range content {
		if content[i] == '\x00' {
			headerEnd = i
			break
		}
	}

	if headerEnd == -1 {
		return "", nil, fmt.Errorf("invalid object format: header not found")
	}

	header := string(content[:headerEnd])
	var objectType string
	var size int
	_, err = fmt.Sscanf(header, "%s %d", &objectType, &size)
	if err != nil {
		return "", nil, fmt.Errorf("invalid object header: %w", err)
	}

	data := content[headerEnd+1:]

	// Verify size
	if len(data) != size {
		return "", nil, fmt.Errorf("object size mismatch: expected %d, got %d", size, len(data))
	}

	return objectType, data, nil
}

// ObjectExists checks if an object exists in the object store.
func ObjectExists(repoRoot, hash string) bool {
	objectPath := GetObjectPath(repoRoot, hash)
	return FileExists(objectPath)
}
