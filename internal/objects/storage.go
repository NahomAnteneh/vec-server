package objects

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Storage handles the storage and retrieval of objects
type Storage struct {
	basePath string
}

// NewStorage creates a new object storage at the given path
func NewStorage(basePath string) *Storage {
	return &Storage{basePath: basePath}
}

// GetObject retrieves an object by its hash
func (s *Storage) GetObject(hash string) (*Object, error) {
	// Validate hash
	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: %s", hash)
	}

	// Get object path
	objectPath := s.getObjectPath(hash)

	// Check if object exists
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	// Open object file
	file, err := os.Open(objectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open object file: %w", err)
	}
	defer file.Close()

	// Create zlib reader
	zlibReader, err := zlib.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zlibReader.Close()

	// Read object data
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zlibReader); err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	// Parse object
	return ParseObject(buf.Bytes())
}

// StoreObject stores an object in the repository
func (s *Storage) StoreObject(obj *Object) error {
	// Get object path
	objectPath := s.getObjectPath(obj.Hash)

	// Create directory if it doesn't exist
	dir := filepath.Dir(objectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create object directory: %w", err)
	}

	// Open file for writing
	file, err := os.Create(objectPath)
	if err != nil {
		return fmt.Errorf("failed to create object file: %w", err)
	}
	defer file.Close()

	// Create zlib writer
	zlibWriter := zlib.NewWriter(file)
	defer zlibWriter.Close()

	// Write object data
	data, err := obj.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize object: %w", err)
	}

	if _, err := zlibWriter.Write(data); err != nil {
		return fmt.Errorf("failed to write object data: %w", err)
	}

	// Flush and close zlib writer
	if err := zlibWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zlib writer: %w", err)
	}

	return nil
}

// GetReachableObjects returns all objects reachable from the given object
func (s *Storage) GetReachableObjects(hash string, depth int) ([]string, error) {
	// For now, just return the hash itself
	// In a real implementation, we would walk the commit graph
	// and include all reachable objects
	return []string{hash}, nil
}

// getObjectPath returns the path to an object file
func (s *Storage) getObjectPath(hash string) string {
	// Use the first two characters as the directory name
	// and the rest as the file name
	return filepath.Join(s.basePath, hash[:2], hash[2:])
}

// HashObject calculates the hash of an object
func HashObject(data []byte, objType ObjectType) (string, error) {
	// Create header
	header := fmt.Sprintf("%s %d\x00", objType.String(), len(data))

	// Calculate hash
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParseObject parses an object from its serialized form
func ParseObject(data []byte) (*Object, error) {
	// Find the null byte that separates header from content
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		return nil, fmt.Errorf("invalid object format: no null byte found")
	}

	// Parse header
	header := string(data[:nullIndex])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid object header: %s", header)
	}

	// Parse object type
	objType, err := ParseObjectType(parts[0])
	if err != nil {
		return nil, err
	}

	// Get content
	content := data[nullIndex+1:]

	// Create object
	obj := &Object{
		Type:    objType,
		Content: content,
	}

	// Calculate hash
	obj.Hash, err = HashObject(content, objType)
	if err != nil {
		return nil, err
	}

	return obj, nil
}
