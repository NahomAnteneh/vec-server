package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// TreeEntry represents a single entry in a tree—either a blob (file) or a subtree.
type TreeEntry struct {
	Mode int32  // File mode (e.g., 0100644 for files, 040000 for trees - stored as octal)
	Name string // Basename (e.g., "file.txt" or directory name)
	Hash string // SHA-256 hash (hex string) of the blob or subtree.
	Type string // "blob" or "tree"
}

// TreeObject represents a Git-style tree object.
type TreeObject struct {
	TreeID  string
	Entries []TreeEntry
}

// NewTreeObject creates a new, empty TreeObject.
func NewTreeObject() *TreeObject {
	return &TreeObject{
		Entries: make([]TreeEntry, 0),
	}
}

// Serialize converts the TreeObject into a Git-compatible byte slice.
// Format: <mode> <n>\x00<hash_bytes> for each entry, sorted by name for deterministic hashing.
func (t *TreeObject) Serialize() ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("cannot serialize nil TreeObject")
	}

	var buf bytes.Buffer

	// Sort entries by name for consistent hashing
	sort.Slice(t.Entries, func(i, j int) bool {
		return t.Entries[i].Name < t.Entries[j].Name
	})

	for _, entry := range t.Entries {
		// Validate entry
		if entry.Name == "" {
			return nil, fmt.Errorf("tree entry has empty name")
		}
		if len(entry.Hash) != 64 { // SHA-256 hash length (hex string)
			return nil, fmt.Errorf("invalid hash length for entry '%s': expected 64, got %d", entry.Name, len(entry.Hash))
		}

		// Write mode as octal string
		modeStr := fmt.Sprintf("%o", entry.Mode)

		// Write mode, space, filename, and null byte
		if _, err := fmt.Fprintf(&buf, "%s %s\x00", modeStr, entry.Name); err != nil {
			return nil, fmt.Errorf("failed to write mode and name for entry '%s': %w", entry.Name, err)
		}

		// Convert hash from hex string to bytes and write
		hashBytes, err := hex.DecodeString(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hash '%s' for entry '%s': %w", entry.Hash, entry.Name, err)
		}

		// Write the 32-byte hash (for SHA-256)
		if _, err := buf.Write(hashBytes); err != nil {
			return nil, fmt.Errorf("failed to write hash for entry '%s': %w", entry.Name, err)
		}
	}

	return buf.Bytes(), nil
}

// DeserializeTreeObject parses a Git-formatted byte slice into a TreeObject.
func DeserializeTreeObject(data []byte) (*TreeObject, error) {
	if data == nil {
		return nil, fmt.Errorf("cannot deserialize nil data")
	}

	// Handle empty tree case
	if len(data) == 0 {
		return NewTreeObject(), nil
	}

	tree := NewTreeObject()
	pos := 0

	for pos < len(data) {
		// Find mode (ends with space)
		spaceIdx := bytes.IndexByte(data[pos:], ' ')
		if spaceIdx == -1 {
			return nil, fmt.Errorf("invalid tree entry: missing space at position %d", pos)
		}
		modeStr := string(data[pos : pos+spaceIdx])
		pos += spaceIdx + 1

		// Find filename (ends with null byte)
		nullIdx := bytes.IndexByte(data[pos:], '\x00')
		if nullIdx == -1 {
			return nil, fmt.Errorf("invalid tree entry: missing null byte at position %d", pos)
		}
		name := string(data[pos : pos+nullIdx])
		if name == "" {
			return nil, fmt.Errorf("invalid tree entry: empty name at position %d", pos)
		}
		pos += nullIdx + 1

		// Check if we have enough bytes for a hash (32 bytes for SHA-256, 20 bytes for SHA-1)
		if pos+32 <= len(data) {
			// We have enough bytes for SHA-256
			hashBytes := data[pos : pos+32]
			pos += 32

			// Parse mode
			mode, err := strconv.ParseInt(modeStr, 8, 32) // Parse octal
			if err != nil {
				return nil, fmt.Errorf("invalid mode '%s' for entry '%s': %w", modeStr, name, err)
			}

			// Determine type based on mode - more reliable check for tree vs blob
			entryType := "blob"
			if mode == 040000 || mode == 040755 || (mode&0040000) == 0040000 {
				entryType = "tree"
			}

			// Convert bytes to hex string
			hexHash := hex.EncodeToString(hashBytes)

			tree.Entries = append(tree.Entries, TreeEntry{
				Mode: int32(mode),
				Name: name,
				Hash: hexHash,
				Type: entryType,
			})
		} else if pos+20 <= len(data) {
			// We have enough bytes for SHA-1 (Git compatibility)
			hashBytes := data[pos : pos+20]
			pos += 20

			// Parse mode
			mode, err := strconv.ParseInt(modeStr, 8, 32) // Parse octal
			if err != nil {
				return nil, fmt.Errorf("invalid mode '%s' for entry '%s': %w", modeStr, name, err)
			}

			// Determine type based on mode - more reliable check for tree vs blob
			entryType := "blob"
			if mode == 040000 || mode == 040755 || (mode&0040000) == 0040000 {
				entryType = "tree"
			}

			// Convert to hex and pad to full SHA-256 length
			hexHash := hex.EncodeToString(hashBytes)
			hexHash = fmt.Sprintf("%s%s", hexHash, strings.Repeat("0", 64-len(hexHash)))

			tree.Entries = append(tree.Entries, TreeEntry{
				Mode: int32(mode),
				Name: name,
				Hash: hexHash,
				Type: entryType,
			})
		} else {
			return nil, fmt.Errorf("invalid tree entry: incomplete hash at position %d for entry '%s'", pos, name)
		}
	}

	return tree, nil
}

// CalculateID calculates and returns the SHA-256 hash (TreeID) of the TreeObject's serialized content.
// This does not set t.TreeID but returns the calculated ID.
func (t *TreeObject) CalculateID() (string, error) {
	if t == nil {
		return "", fmt.Errorf("cannot calculate ID of nil TreeObject")
	}
	data, err := t.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize tree for ID calculation: %w", err)
	}
	// The hash is of the tree data itself with header using Vec's HashBytes function
	// which properly adds the "tree <size>\x00" header.
	return HashBytes("tree", data), nil
}

// CreateTreeObject creates a tree object from a slice of TreeEntry objects.
// It serializes the entries and writes them to the repository.
func (repo *Repository) CreateTree(entries []TreeEntry) (string, error) {
	// Create a tree object and use its serialization method for consistency
	tree := &TreeObject{
		Entries: entries,
	}

	// Use the standardized serialization method
	treeData, err := tree.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize tree: %w", err)
	}

	// Write the tree object
	hash, err := repo.WriteObject("tree", treeData)
	if err != nil {
		return "", fmt.Errorf("failed to write tree object: %w", err)
	}

	return hash, nil
}

// CreateTree creates a tree object from a slice of TreeEntry objects using the repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateTree(repoRoot string, entries []TreeEntry) (string, error) {
	repo := NewRepository(repoRoot)
	return repo.CreateTree(entries)
}

// GetTree retrieves and deserializes a TreeObject from disk using Repository context.
func (repo *Repository) GetTree(hash string) (*TreeObject, error) {
	if repo == nil {
		return nil, fmt.Errorf("nil repository passed to GetTree")
	}

	if len(hash) != 64 || !IsValidHex(hash) { // Ensure hash is valid hex and correct length
		return nil, ObjectError(fmt.Sprintf("invalid tree hash format: '%s'", hash), nil)
	}

	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, fmt.Sprintf("tree %s", hash))
		}
		return nil, ObjectError(fmt.Sprintf("failed to read tree object %s: %s", hash, err.Error()), err)
	}

	if objectType != "tree" {
		return nil, ObjectError(fmt.Sprintf("object %s is not a tree, but a %s", hash, objectType), nil)
	}

	tree, err := DeserializeTreeObject(data)
	if err != nil {
		return nil, ObjectError(fmt.Sprintf("failed to deserialize tree %s: %s", hash, err.Error()), err)
	}

	tree.TreeID = hash // Set the ID from the hash used to retrieve it.
	return tree, nil
}

// GetTree retrieves and deserializes a TreeObject from disk given its hash.
func GetTree(repoRoot string, hash string) (*TreeObject, error) {
	if hash == "" {
		return nil, fmt.Errorf("empty hash passed to GetTree")
	}

	repo := NewRepository(repoRoot)
	return repo.GetTree(hash)
}

// CollectTreeEntries recursively collects all blob entries from a tree and subtrees
func CollectTreeEntries(repoRoot string, tree *TreeObject, prefix string, entries map[string]TreeEntry) error {
	if tree == nil {
		return fmt.Errorf("nil tree object encountered for path: %s", prefix)
	}

	for _, entry := range tree.Entries {
		entryPath := filepath.Join(prefix, entry.Name)
		entries[entryPath] = entry

		if entry.Type == "tree" {
			subTree, err := GetTree(repoRoot, entry.Hash)
			if err != nil {
				// Log the error but try to continue with other entries
				fmt.Fprintf(os.Stderr, "warning: failed to get subtree %s for entry %s: %v\n", entry.Hash, entryPath, err)
				continue
			}
			if err := CollectTreeEntries(repoRoot, subTree, entryPath, entries); err != nil {
				// Log the error but try to continue with other entries
				fmt.Fprintf(os.Stderr, "warning: error processing subtree %s: %v\n", entryPath, err)
				continue
			}
		}
	}
	return nil
}
