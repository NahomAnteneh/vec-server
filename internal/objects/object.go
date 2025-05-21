package objects

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// VecDirName is the name of the Vec directory
	VecDirName = ".vec"
)

// ObjectType represents the type of a Vec object
type ObjectType int

const (
	// ObjectTypeBlob represents a blob object
	ObjectTypeBlob ObjectType = iota
	// ObjectTypeTree represents a tree object
	ObjectTypeTree
	// ObjectTypeCommit represents a commit object
	ObjectTypeCommit
	// ObjectTypeTag represents a tag object
	ObjectTypeTag
)

// String returns the string representation of an object type
func (t ObjectType) String() string {
	switch t {
	case ObjectTypeBlob:
		return "blob"
	case ObjectTypeTree:
		return "tree"
	case ObjectTypeCommit:
		return "commit"
	case ObjectTypeTag:
		return "tag"
	default:
		return "unknown"
	}
}

// ParseObjectType parses an object type from a string
func ParseObjectType(s string) (ObjectType, error) {
	switch s {
	case "blob":
		return ObjectTypeBlob, nil
	case "tree":
		return ObjectTypeTree, nil
	case "commit":
		return ObjectTypeCommit, nil
	case "tag":
		return ObjectTypeTag, nil
	default:
		return 0, fmt.Errorf("unknown object type: %s", s)
	}
}

// Object represents a Vec object
type Object struct {
	Hash    string
	Type    ObjectType
	Content []byte
	// For delta objects
	BaseHash string
}

// Serialize serializes an object to bytes
func (o *Object) Serialize() ([]byte, error) {
	header := fmt.Sprintf("%s %d\x00", o.Type.String(), len(o.Content))
	result := make([]byte, len(header)+len(o.Content))
	copy(result, []byte(header))
	copy(result[len(header):], o.Content)
	return result, nil
}

// HashFile calculates the SHA-256 hash of a file, including the Vec object header.
func HashFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
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
	if err := os.MkdirAll(objectDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create object directory: %w", err)
	}

	// Don't overwrite existing objects (idempotent operation)
	if _, err := os.Stat(objectPath); err == nil {
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
	content, err := os.ReadFile(objectPath)
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
	_, err := os.Stat(objectPath)
	return err == nil
}
