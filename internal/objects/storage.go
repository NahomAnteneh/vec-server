package objects

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PackfileInfo holds metadata about a packfile
type PackfileInfo struct {
	Path        string
	ObjectCount int
	IndexPath   string
	Objects     map[string]int64 // Map of hash to offset in packfile
}

// PackfileHeader represents the header of a packfile
type PackfileHeader struct {
	Signature  [4]byte // "PACK"
	Version    uint32  // Version (1)
	NumObjects uint32  // Number of objects
}

// PackfileIndexEntry represents an entry in the packfile index
type PackfileIndexEntry struct {
	Hash   string
	Offset int64
}

// Storage handles the storage and retrieval of objects
type Storage struct {
	basePath string
	// Object cache for performance
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

		// Read packfile header for object count
		packInfo, err := s.readPackfileInfo(packPath, indexPath)
		if err != nil {
			continue // Skip problematic packfiles
		}

		s.packfiles = append(s.packfiles, packInfo)
	}
}

// readPackfileInfo reads information about a packfile and its index
func (s *Storage) readPackfileInfo(packPath, indexPath string) (PackfileInfo, error) {
	// Open packfile
	file, err := os.Open(packPath)
	if err != nil {
		return PackfileInfo{}, err
	}
	defer file.Close()

	// Read header
	var header PackfileHeader
	if err := binary.Read(file, binary.BigEndian, &header); err != nil {
		return PackfileInfo{}, err
	}

	// Validate signature
	if string(header.Signature[:]) != "PACK" {
		return PackfileInfo{}, fmt.Errorf("invalid packfile signature")
	}

	// Read index
	objects, err := s.readPackfileIndex(indexPath)
	if err != nil {
		return PackfileInfo{}, err
	}

	return PackfileInfo{
		Path:        packPath,
		IndexPath:   indexPath,
		ObjectCount: int(header.NumObjects),
		Objects:     objects,
	}, nil
}

// readPackfileIndex reads the packfile index and returns a map of object hash to offset
func (s *Storage) readPackfileIndex(indexPath string) (map[string]int64, error) {
	// Open index file
	file, err := os.Open(indexPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read index header (signature + version)
	var signature [4]byte
	var version uint32
	if err := binary.Read(file, binary.BigEndian, &signature); err != nil {
		return nil, err
	}
	if string(signature[:]) != "VIDX" {
		return nil, fmt.Errorf("invalid index signature")
	}
	if err := binary.Read(file, binary.BigEndian, &version); err != nil {
		return nil, err
	}

	// Read number of objects
	var numObjects uint32
	if err := binary.Read(file, binary.BigEndian, &numObjects); err != nil {
		return nil, err
	}

	// Read entries
	objects := make(map[string]int64)
	for i := 0; i < int(numObjects); i++ {
		// Read hash (32 bytes for SHA-256)
		hashBytes := make([]byte, 32)
		if _, err := io.ReadFull(file, hashBytes); err != nil {
			return nil, err
		}

		// Read offset
		var offset int64
		if err := binary.Read(file, binary.BigEndian, &offset); err != nil {
			return nil, err
		}

		// Convert hash to hex string
		hash := hex.EncodeToString(hashBytes)
		objects[hash] = offset
	}

	return objects, nil
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

	return nil, fmt.Errorf("object not found: %s", err)
}

// getLooseObject retrieves a loose object by its hash
func (s *Storage) getLooseObject(hash string) (*Object, error) {
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

// getPackedObject retrieves an object from packfiles by its hash
func (s *Storage) getPackedObject(hash string) (*Object, error) {
	s.mu.RLock()
	packfiles := make([]PackfileInfo, len(s.packfiles))
	copy(packfiles, s.packfiles)
	s.mu.RUnlock()

	// Try each packfile until we find the object
	for _, packInfo := range packfiles {
		// Check if object exists in this packfile
		offset, exists := packInfo.Objects[hash]
		if !exists {
			continue
		}

		// Get object from packfile
		obj, err := s.getObjectFromPackfile(hash, packInfo.Path, offset)
		if err == nil {
			return obj, nil
		}
		// Continue to next packfile if error retrieving from this one
	}

	return nil, fmt.Errorf("object not found in any packfile: %s", hash)
}

// getObjectFromPackfile retrieves an object from a specific packfile at the given offset
func (s *Storage) getObjectFromPackfile(hash, packfilePath string, offset int64) (*Object, error) {
	// Open packfile
	file, err := os.Open(packfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open packfile: %w", err)
	}
	defer file.Close()

	// Seek to object position
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to object: %w", err)
	}

	// Read object type and size
	var objectType byte
	var objectSize uint32
	if err := binary.Read(file, binary.BigEndian, &objectType); err != nil {
		return nil, fmt.Errorf("failed to read object type: %w", err)
	}
	if err := binary.Read(file, binary.BigEndian, &objectSize); err != nil {
		return nil, fmt.Errorf("failed to read object size: %w", err)
	}

	// Create zlib reader for the object data
	zlibReader, err := zlib.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zlibReader.Close()

	// Read compressed data
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, zlibReader); err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	// Parse object
	obj, err := ParseObject(buf.Bytes())
	if err != nil {
		return nil, err
	}

	// Verify hash
	if obj.Hash != hash {
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", hash, obj.Hash)
	}

	return obj, nil
}

// StoreObject stores an object in the repository
func (s *Storage) StoreObject(obj *Object) error {
	// Get object path
	objectPath := s.getObjectPath(obj.Hash)

	// If object already exists, no need to store it again (idempotent operation)
	if _, err := os.Stat(objectPath); err == nil {
		return nil
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(objectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create object directory: %w", err)
	}

	// Create a temporary file first
	tempFile := objectPath + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary object file: %w", err)
	}
	defer func() {
		file.Close()
		// Clean up the temp file if something went wrong
		if _, err := os.Stat(tempFile); err == nil {
			os.Remove(tempFile)
		}
	}()

	// Create zlib writer for compression
	zlibWriter := zlib.NewWriter(file)

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

	// Close the file
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close object file: %w", err)
	}

	// Atomically move the temp file to the final location
	if err := os.Rename(tempFile, objectPath); err != nil {
		return fmt.Errorf("failed to finalize object file: %w", err)
	}

	// Set file permissions to read-only
	if err := os.Chmod(objectPath, 0444); err != nil {
		return fmt.Errorf("failed to set permissions on object file: %w", err)
	}

	// Add to cache
	s.cacheMu.Lock()
	s.objectCache[obj.Hash] = obj
	s.cacheMu.Unlock()

	return nil
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
	objectPath := s.getObjectPath(hash)
	if _, err := os.Stat(objectPath); err == nil {
		return true
	}

	// Check packfiles
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, packInfo := range s.packfiles {
		if _, exists := packInfo.Objects[hash]; exists {
			return true
		}
	}

	return false
}

// GetReachableObjects returns all objects reachable from the given object
func (s *Storage) GetReachableObjects(hash string, depth int) ([]string, error) {
	if depth <= 0 {
		return []string{hash}, nil
	}

	// Get the object
	obj, err := s.GetObject(hash)
	if err != nil {
		return nil, err
	}

	reachable := []string{hash}

	// If it's a commit, follow its tree and parents
	if obj.Type == ObjectTypeCommit {
		commit := &Commit{}
		if err := commit.Parse(append([]byte("commit "+fmt.Sprint(len(obj.Content))+"\x00"), obj.Content...)); err != nil {
			return reachable, nil
		}

		// Add tree
		treeObjs, err := s.GetReachableObjects(commit.TreeHash, depth-1)
		if err == nil {
			reachable = append(reachable, treeObjs...)
		}

		// Add parents (with same depth since we're traversing history)
		for _, parent := range commit.Parents {
			parentObjs, err := s.GetReachableObjects(parent, depth)
			if err == nil {
				reachable = append(reachable, parentObjs...)
			}
		}
	} else if obj.Type == ObjectTypeTree {
		// If it's a tree, follow its entries
		tree := &Tree{}
		if err := tree.Parse(append([]byte("tree "+fmt.Sprint(len(obj.Content))+"\x00"), obj.Content...)); err != nil {
			return reachable, nil
		}

		// Add all entries
		for _, entry := range tree.Entries {
			entryObjs, err := s.GetReachableObjects(entry.Hash, depth-1)
			if err == nil {
				reachable = append(reachable, entryObjs...)
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var result []string

	for _, h := range reachable {
		if !seen[h] {
			seen[h] = true
			result = append(result, h)
		}
	}

	return result, nil
}

// getObjectPath returns the path to an object file
func (s *Storage) getObjectPath(hash string) string {
	// Use the first two characters as the directory name
	// and the rest as the file name (to match client expectations)
	// Path structure: .vec/objects/<first-2-bytes>/<remaining-bytes>
	return filepath.Join(s.basePath, VecDirName, "objects", hash[:2], hash[2:])
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

	// Generate packfile name based on current time and content hash
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	packName := fmt.Sprintf("pack-%s.pack", timestamp)
	packPath := filepath.Join(packDir, packName)
	indexPath := packPath[:len(packPath)-5] + ".idx" // Replace .pack with .idx

	// Create a temporary packfile
	tempPackFile := packPath + ".tmp"
	packFile, err := os.Create(tempPackFile)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary packfile: %w", err)
	}
	defer func() {
		packFile.Close()
		// Clean up temp files if something went wrong
		if _, err := os.Stat(tempPackFile); err == nil {
			os.Remove(tempPackFile)
		}
	}()

	// Create a temporary index file
	tempIndexFile := indexPath + ".tmp"
	indexFile, err := os.Create(tempIndexFile)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary index file: %w", err)
	}
	defer func() {
		indexFile.Close()
		if _, err := os.Stat(tempIndexFile); err == nil {
			os.Remove(tempIndexFile)
		}
	}()

	// Write packfile header (signature, version, object count)
	signature := []byte("PACK")
	version := uint32(1) // Version 1
	count := uint32(len(objects))

	// Write header to packfile
	if _, err := packFile.Write(signature); err != nil {
		return "", fmt.Errorf("failed to write packfile signature: %w", err)
	}
	if err := binary.Write(packFile, binary.BigEndian, version); err != nil {
		return "", fmt.Errorf("failed to write packfile version: %w", err)
	}
	if err := binary.Write(packFile, binary.BigEndian, count); err != nil {
		return "", fmt.Errorf("failed to write packfile object count: %w", err)
	}

	// Write index header
	indexSignature := []byte("VIDX") // Vec Index signature
	if _, err := indexFile.Write(indexSignature); err != nil {
		return "", fmt.Errorf("failed to write index signature: %w", err)
	}
	if err := binary.Write(indexFile, binary.BigEndian, version); err != nil {
		return "", fmt.Errorf("failed to write index version: %w", err)
	}
	if err := binary.Write(indexFile, binary.BigEndian, count); err != nil {
		return "", fmt.Errorf("failed to write index object count: %w", err)
	}

	// Process objects
	objectOffsets := make(map[string]int64)
	for _, obj := range objects {
		// Get current offset for index
		offset, err := packFile.Seek(0, io.SeekCurrent)
		if err != nil {
			return "", fmt.Errorf("failed to get packfile offset: %w", err)
		}

		// Store object offset for index
		objectOffsets[obj.Hash] = offset

		// Write object type
		var objTypeByte byte
		switch obj.Type {
		case ObjectTypeBlob:
			objTypeByte = 1
		case ObjectTypeTree:
			objTypeByte = 2
		case ObjectTypeCommit:
			objTypeByte = 3
		case ObjectTypeTag:
			objTypeByte = 4
		default:
			return "", fmt.Errorf("invalid object type: %s", obj.Type)
		}
		if err := binary.Write(packFile, binary.BigEndian, objTypeByte); err != nil {
			return "", fmt.Errorf("failed to write object type: %w", err)
		}

		// Write object size
		objSize := uint32(len(obj.Content))
		if err := binary.Write(packFile, binary.BigEndian, objSize); err != nil {
			return "", fmt.Errorf("failed to write object size: %w", err)
		}

		// Serialize object
		data, err := obj.Serialize()
		if err != nil {
			return "", fmt.Errorf("failed to serialize object: %w", err)
		}

		// Create zlib writer for this object
		zlibWriter := zlib.NewWriter(packFile)
		if _, err := zlibWriter.Write(data); err != nil {
			return "", fmt.Errorf("failed to write object data: %w", err)
		}
		if err := zlibWriter.Close(); err != nil {
			return "", fmt.Errorf("failed to close zlib writer: %w", err)
		}
	}

	// Write index entries
	for _, obj := range objects {
		// Convert hash string to bytes
		hashBytes, err := hex.DecodeString(obj.Hash)
		if err != nil {
			return "", fmt.Errorf("failed to decode hash: %w", err)
		}

		// Write hash
		if _, err := indexFile.Write(hashBytes); err != nil {
			return "", fmt.Errorf("failed to write hash to index: %w", err)
		}

		// Write offset
		offset := objectOffsets[obj.Hash]
		if err := binary.Write(indexFile, binary.BigEndian, offset); err != nil {
			return "", fmt.Errorf("failed to write offset to index: %w", err)
		}
	}

	// Calculate packfile checksum
	if _, err := packFile.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to start of packfile: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, packFile); err != nil {
		return "", fmt.Errorf("failed to calculate packfile checksum: %w", err)
	}
	checksum := hasher.Sum(nil)

	// Write checksum to end of packfile
	if _, err := packFile.Seek(0, io.SeekEnd); err != nil {
		return "", fmt.Errorf("failed to seek to end of packfile: %w", err)
	}
	if _, err := packFile.Write(checksum); err != nil {
		return "", fmt.Errorf("failed to write packfile checksum: %w", err)
	}

	// Write checksum to end of index
	if _, err := indexFile.Write(checksum); err != nil {
		return "", fmt.Errorf("failed to write index checksum: %w", err)
	}

	// Close files
	if err := packFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close packfile: %w", err)
	}
	if err := indexFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close index file: %w", err)
	}

	// Atomically move temp files to final locations
	if err := os.Rename(tempPackFile, packPath); err != nil {
		return "", fmt.Errorf("failed to finalize packfile: %w", err)
	}
	if err := os.Rename(tempIndexFile, indexPath); err != nil {
		return "", fmt.Errorf("failed to finalize index file: %w", err)
	}

	// Set file permissions
	if err := os.Chmod(packPath, 0444); err != nil {
		return "", fmt.Errorf("failed to set permissions on packfile: %w", err)
	}
	if err := os.Chmod(indexPath, 0444); err != nil {
		return "", fmt.Errorf("failed to set permissions on index file: %w", err)
	}

	// Create map of objects for the PackfileInfo
	objectMap := make(map[string]int64)
	for _, obj := range objects {
		objectMap[obj.Hash] = objectOffsets[obj.Hash]
	}

	// Add packfile to list
	s.mu.Lock()
	s.packfiles = append(s.packfiles, PackfileInfo{
		Path:        packPath,
		IndexPath:   indexPath,
		ObjectCount: len(objects),
		Objects:     objectMap,
	})
	s.mu.Unlock()

	return packPath, nil
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
	obj.Hash, err = HashObject(content, objType)
	if err != nil {
		return nil, err
	}

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
		os.Remove(looseObjectPath)
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
		// Open packfile
		file, err := os.Open(packInfo.Path)
		if err != nil {
			invalidPackfiles = append(invalidPackfiles, packInfo.Path)
			continue
		}

		// Calculate checksum
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			file.Close()
			invalidPackfiles = append(invalidPackfiles, packInfo.Path)
			continue
		}

		file.Close()

		// Verify each object
		for hash := range packInfo.Objects {
			obj, err := s.getObjectFromPackfile(hash, packInfo.Path, packInfo.Objects[hash])
			if err != nil || obj.Hash != hash {
				invalidPackfiles = append(invalidPackfiles, packInfo.Path)
				break
			}
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
	err := filepath.WalkDir(objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			// Count only regular files
			if filepath.Dir(filepath.Dir(path)) == objectsDir {
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
	for _, packInfo := range s.packfiles {
		info, err := os.Stat(packInfo.Path)
		if err == nil {
			totalSize += info.Size()
		}
	}

	return looseCount, packCount, totalSize, nil
}
