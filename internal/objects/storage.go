package objects

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
)

// Constants
const (
	VecDirName = ".vec"
)

// Object represents an object in the repository
type Object struct {
	Hash    string // SHA-256 hash of the object
	Type    string // Type of the object (blob, tree, commit, tag)
	Content []byte // Content of the object
}

// PackfileInfo is a lightweight wrapper around packfile package's data
type PackfileInfo struct {
	Path        string
	ObjectCount int
	IndexPath   string
	Objects     map[string]int64 // Map of hash to offset in packfile
	Index       *packfile.PackfileIndex
}

// Storage handles the storage and retrieval of objects
type Storage struct {
	basePath    string
	objectCache map[string]*Object
	packfiles   []PackfileInfo
	mu          sync.RWMutex // For thread safety
	cacheMu     sync.RWMutex // For cache access
}

// NewStorage creates a new object storage at the given path
func NewStorage(basePath string) *Storage {
	s := &Storage{
		basePath:    basePath,
		objectCache: make(map[string]*Object),
	}
	// Scan for packfiles on initialization
	s.scanPackfiles()
	return s
}

// scanPackfiles scans for packfiles in the packfiles directory
func (s *Storage) scanPackfiles() {
	packDir := filepath.Join(s.basePath, VecDirName, "objects", "pack")

	// Ensure the directory exists
	if _, err := os.Stat(packDir); os.IsNotExist(err) {
		return // No packfiles directory yet
	}

	// Find all .pack files
	files, err := os.ReadDir(packDir)
	if err != nil {
		return // Unable to read directory
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.packfiles = nil // Reset the list

	for _, file := range files {
		filename := file.Name()
		if !strings.HasSuffix(filename, ".pack") {
			continue
		}

		packPath := filepath.Join(packDir, filename)
		indexPath := packPath[:len(packPath)-5] + ".idx" // Replace .pack with .idx

		// Check if index exists
		if _, err := os.Stat(indexPath); os.IsNotExist(err) {
			continue // Skip packfiles without index
		}

		// Read packfile index using packfile package
		index, err := packfile.ReadPackIndex(indexPath)
		if err != nil {
			continue // Skip problematic packfiles
		}

		// Convert from packfile.PackIndexEntry to our offset map
		objects := make(map[string]int64)
		for hash, entry := range index.Entries {
			objects[hash] = int64(entry.Offset)
		}

		// Store packfile info
		s.packfiles = append(s.packfiles, PackfileInfo{
			Path:        packPath,
			IndexPath:   indexPath,
			ObjectCount: len(index.Entries),
			Objects:     objects,
			Index:       index,
		})
	}
}

// GetObject retrieves an object by its hash
func (s *Storage) GetObject(hash string) (*Object, error) {
	// Validate hash
	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: %s", hash)
	}

	// Check cache first
	s.cacheMu.RLock()
	if obj, ok := s.objectCache[hash]; ok {
		s.cacheMu.RUnlock()
		return obj, nil
	}
	s.cacheMu.RUnlock()

	// First try to get from loose objects
	obj, err := s.getLooseObject(hash)
	if err == nil {
		// Add to cache
		s.cacheMu.Lock()
		s.objectCache[hash] = obj
		s.cacheMu.Unlock()
		return obj, nil
	}

	// If not found as loose object, try packfiles
	obj, err = s.getPackedObject(hash)
	if err == nil {
		// Add to cache
		s.cacheMu.Lock()
		s.objectCache[hash] = obj
		s.cacheMu.Unlock()
		return obj, nil
	}

	return nil, fmt.Errorf("object not found: %s", hash)
}

// getLooseObject retrieves a loose object by its hash
func (s *Storage) getLooseObject(hash string) (*Object, error) {
	// Get object path
	objectPath := s.getObjectPath(hash)

	// Check if object exists
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	// Use the core package to read the object
	objectType, data, err := core.ReadObject(s.basePath, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to read object: %w", err)
	}

	return &Object{
		Hash:    hash,
		Type:    objectType,
		Content: data,
	}, nil
}

// getPackedObject retrieves an object from packfiles by its hash
func (s *Storage) getPackedObject(hash string) (*Object, error) {
	s.mu.RLock()
	if len(s.packfiles) == 0 {
		s.mu.RUnlock()
		return nil, fmt.Errorf("no packfiles available")
	}

	packfiles := make([]PackfileInfo, len(s.packfiles))
	copy(packfiles, s.packfiles)
	s.mu.RUnlock()

	// Try each packfile until we find the object
	for _, packInfo := range packfiles {
		// Check if object exists in this packfile
		if _, exists := packInfo.Objects[hash]; !exists {
			continue
		}

		// Parse the packfile to get the object
		objects, err := packfile.ParseModernPackfile(packInfo.Path, true)
		if err != nil {
			continue // Skip problematic packfiles
		}

		// Find the object in the parsed packfile
		for _, obj := range objects {
			if obj.Hash == hash {
				// Convert packfile.Object to our Object type
				return &Object{
					Hash:    obj.Hash,
					Type:    packfileTypeToString(obj.Type),
					Content: obj.Data,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("object not found in any packfile: %s", hash)
}

// packfileTypeToString converts packfile.ObjectType to string
func packfileTypeToString(objType packfile.ObjectType) string {
	switch objType {
	case packfile.OBJ_COMMIT:
		return "commit"
	case packfile.OBJ_TREE:
		return "tree"
	case packfile.OBJ_BLOB:
		return "blob"
	case packfile.OBJ_TAG:
		return "tag"
	default:
		return "unknown"
	}
}

// StoreObject stores an object in the repository
func (s *Storage) StoreObject(obj *Object) error {
	if obj == nil {
		return fmt.Errorf("cannot store nil object")
	}

	// Use the core package to store the object
	_, err := core.WriteObject(s.basePath, obj.Type, obj.Content)
	if err != nil {
		return fmt.Errorf("failed to store object: %w", err)
	}

	// Add to cache
	s.cacheMu.Lock()
	s.objectCache[obj.Hash] = obj
	s.cacheMu.Unlock()

	return nil
}

// objectExistsInPackfile checks if an object exists in any packfile
func (s *Storage) objectExistsInPackfile(hash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, packInfo := range s.packfiles {
		if _, exists := packInfo.Objects[hash]; exists {
			return true
		}
	}

	return false
}

// ObjectExists checks if an object exists in the storage
func (s *Storage) ObjectExists(hash string) bool {
	// Check cache first
	s.cacheMu.RLock()
	if _, ok := s.objectCache[hash]; ok {
		s.cacheMu.RUnlock()
		return true
	}
	s.cacheMu.RUnlock()

	// Check loose objects
	if core.ObjectExists(s.basePath, hash) {
		return true
	}

	// Check packfiles
	return s.objectExistsInPackfile(hash)
}

// GetReachableObjects returns all objects reachable from the given object
func (s *Storage) GetReachableObjects(hash string, depth int) ([]string, error) {
	if depth <= 0 {
		return []string{hash}, nil
	}

	// Check if the object exists
	if exists := s.ObjectExists(hash); !exists {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	// Just return the hash itself for simplicity
	// For a more complete implementation, use the core package's functionality
	return []string{hash}, nil
}

// getObjectPath returns the path to an object file
func (s *Storage) getObjectPath(hash string) string {
	return core.GetObjectPath(s.basePath, hash)
}

// CreatePackfile creates a packfile containing the given objects
func (s *Storage) CreatePackfile(objects []*Object) (string, error) {
	if len(objects) == 0 {
		return "", fmt.Errorf("cannot create an empty packfile")
	}

	// Create packfile directory if it doesn't exist
	packDir := filepath.Join(s.basePath, VecDirName, "objects", "pack")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create packfile directory: %w", err)
	}

	// Generate packfile name based on current time
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	packName := fmt.Sprintf("pack-%s.pack", timestamp)
	packPath := filepath.Join(packDir, packName)

	// Convert Object to packfile.Object
	packObjects := make([]packfile.Object, len(objects))
	for i, obj := range objects {
		packObjects[i] = packfile.Object{
			Hash: obj.Hash,
			Type: stringToPackfileType(obj.Type),
			Data: obj.Content,
		}
	}

	// Create packfile using the packfile package
	if err := packfile.CreateModernPackfile(packObjects, packPath); err != nil {
		return "", fmt.Errorf("failed to create packfile: %w", err)
	}

	// Reload packfiles to include the new one
	s.scanPackfiles()

	return packPath, nil
}

// stringToPackfileType converts string type to packfile.ObjectType
func stringToPackfileType(objType string) packfile.ObjectType {
	switch objType {
	case "commit":
		return packfile.OBJ_COMMIT
	case "tree":
		return packfile.OBJ_TREE
	case "blob":
		return packfile.OBJ_BLOB
	case "tag":
		return packfile.OBJ_TAG
	default:
		return packfile.OBJ_NONE
	}
}

// HashObject calculates the hash of an object
func HashObject(data []byte, objType string) (string, error) {
	// Create header
	header := fmt.Sprintf("%s %d\x00", objType, len(data))

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
	objType := parts[0]

	// Parse size
	var size int
	if _, err := fmt.Sscanf(parts[1], "%d", &size); err != nil {
		return nil, fmt.Errorf("invalid object size: %s", parts[1])
	}

	// Get content
	content := data[nullIndex+1:]

	// Verify size
	if len(content) != size {
		return nil, fmt.Errorf("object size mismatch: expected %d, got %d", size, len(content))
	}

	// Create object
	obj := &Object{
		Type:    objType,
		Content: content,
	}

	// Calculate hash
	obj.Hash, _ = HashObject(content, objType)

	return obj, nil
}

// GarbageCollect performs garbage collection by packing loose objects
func (s *Storage) GarbageCollect() (int, error) {
	objectsDir := filepath.Join(s.basePath, VecDirName, "objects")

	// Collect all loose objects
	var looseObjects []*Object

	// Walk through the objects directory
	err := filepath.WalkDir(objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-regular files
		if d.IsDir() || path == objectsDir || filepath.Base(filepath.Dir(path)) == "pack" {
			return nil
		}

		// Extract hash from path
		prefix := filepath.Base(filepath.Dir(path))
		suffix := filepath.Base(path)
		if len(prefix) != 2 || len(suffix) != 62 {
			return nil // Not a loose object
		}

		hash := prefix + suffix

		// Skip if object is already in a packfile
		if s.objectExistsInPackfile(hash) {
			return nil
		}

		// Load the object
		obj, err := s.getLooseObject(hash)
		if err != nil {
			return nil // Skip problematic objects
		}

		looseObjects = append(looseObjects, obj)
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to collect loose objects: %w", err)
	}

	if len(looseObjects) == 0 {
		return 0, nil // Nothing to do
	}

	// Create packfile
	_, err = s.CreatePackfile(looseObjects)
	if err != nil {
		return 0, fmt.Errorf("failed to create packfile: %w", err)
	}

	// Count of packed objects
	packedCount := len(looseObjects)

	// Delete loose objects that were packed
	for _, obj := range looseObjects {
		looseObjectPath := s.getObjectPath(obj.Hash)
		err := os.Remove(looseObjectPath)
		if err != nil && !os.IsNotExist(err) {
			// Log error but continue with other objects
			fmt.Printf("Warning: failed to remove loose object %s: %v\n", obj.Hash, err)
		}
	}

	return packedCount, nil
}

// ClearCache clears the object cache
func (s *Storage) ClearCache() {
	s.cacheMu.Lock()
	s.objectCache = make(map[string]*Object)
	s.cacheMu.Unlock()
}

// VerifyPackfiles verifies the integrity of all packfiles
func (s *Storage) VerifyPackfiles() ([]string, error) {
	s.mu.RLock()
	packfiles := make([]PackfileInfo, len(s.packfiles))
	copy(packfiles, s.packfiles)
	s.mu.RUnlock()

	var invalidPackfiles []string

	for _, packInfo := range packfiles {
		// Use the packfile package to verify the packfile
		if err := packfile.VerifyPackIndex(packInfo.IndexPath, packInfo.Path); err != nil {
			invalidPackfiles = append(invalidPackfiles, packInfo.Path)
		}
	}

	return invalidPackfiles, nil
}

// GetStatistics returns statistics about the object storage
func (s *Storage) GetStatistics() (int, int, int64, error) {
	s.mu.RLock()
	packCount := len(s.packfiles)
	s.mu.RUnlock()

	// Count loose objects
	looseCount := 0
	totalSize := int64(0)

	objectsDir := filepath.Join(s.basePath, VecDirName, "objects")

	// Check if directory exists
	if _, err := os.Stat(objectsDir); os.IsNotExist(err) {
		return 0, packCount, 0, nil
	}

	err := filepath.WalkDir(objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Continue walking even if error for one file
		}

		if !d.IsDir() {
			// Count only regular files
			dirPath := filepath.Dir(path)
			parentDir := filepath.Base(dirPath)

			if len(parentDir) == 2 && parentDir != "pack" {
				info, err := d.Info()
				if err != nil {
					return nil // Skip if can't get info
				}

				looseCount++
				totalSize += info.Size()
			}
		}
		return nil
	})

	if err != nil {
		return 0, 0, 0, err
	}

	// Add packfile sizes
	s.mu.RLock()
	packfiles := make([]PackfileInfo, len(s.packfiles))
	copy(packfiles, s.packfiles)
	s.mu.RUnlock()

	for _, packInfo := range packfiles {
		info, err := os.Stat(packInfo.Path)
		if err == nil {
			totalSize += info.Size()
		}
	}

	return looseCount, packCount, totalSize, nil
}

// ReadObject reads an object from a repository by its hash
func ReadObject(repoPath string, hash string) (string, []byte, error) {
	// We need to get the objects path, which is repoPath/.vec/objects
	objectsPath := filepath.Join(repoPath, VecDirName, "objects")

	// Create a new storage instance
	storage := NewStorage(objectsPath)

	// Get the object
	obj, err := storage.GetObject(hash)
	if err != nil {
		return "", nil, err
	}

	// Return the object type as string and its content
	return obj.Type, obj.Content, nil
}
