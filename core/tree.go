package core

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Vec-compatible file modes (octal)
const (
	ModeFileRegular    = 0100644 // Regular file, non-executable (rw-r--r--)
	ModeFileExecutable = 0100755 // Executable file (rwxr-xr-x)
	ModeTree           = 0040000 // Directory (tree)
	ModeSymlink        = 0120000 // Symbolic link
)

// ValidModes is the set of allowed Vec-compatible modes.
var ValidModes = map[int32]bool{
	ModeFileRegular:    true,
	ModeFileExecutable: true,
	ModeTree:           true,
	ModeSymlink:        true,
}

// TreeEntry represents a single entry in a tree (blob or subtree).
type TreeEntry struct {
	Mode int32  // Vec-compatible mode (e.g., 0100644, 0040000)
	Name string // Basename (e.g., "file.txt" or directory name)
	Hash string // SHA-256 hash (hex string)
	Type string // "blob", "tree", or "symlink"
}

// TreeObject represents a Vec-style tree object.
type TreeObject struct {
	TreeID  string
	Entries []TreeEntry
}

// NewTreeObject creates a new, empty TreeObject.
func NewTreeObject() *TreeObject {
	return &TreeObject{
		Entries: make([]TreeEntry, 0, 10),
	}
}

// Serialize converts the TreeObject into a Vec-compatible byte slice.
func (t *TreeObject) Serialize() ([]byte, error) {
	if t == nil {
		return nil, ObjectError("nil TreeObject", nil)
	}
	var buf bytes.Buffer
	entries := make([]TreeEntry, len(t.Entries))
	copy(entries, t.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	for _, entry := range entries {
		if entry.Name == "" {
			return nil, ObjectError("tree entry has empty name", nil)
		}
		if len(entry.Hash) != 64 || !IsValidHex(entry.Hash) {
			return nil, ObjectError("invalid hash for entry: "+entry.Name, nil)
		}
		if !ValidModes[entry.Mode] {
			return nil, ObjectError("invalid mode for entry: "+entry.Name, nil)
		}
		if !isValidEntryType(entry.Type, entry.Mode) {
			return nil, ObjectError("mismatched type and mode for entry: "+entry.Name, nil)
		}
		if _, err := fmt.Fprintf(&buf, "%o %s\x00", entry.Mode, entry.Name); err != nil {
			return nil, ObjectError("failed to write entry: "+entry.Name, err)
		}
		hashBytes, err := hex.DecodeString(entry.Hash)
		if err != nil {
			return nil, ObjectError("failed to decode hash for entry: "+entry.Name, err)
		}
		if _, err := buf.Write(hashBytes); err != nil {
			return nil, ObjectError("failed to write hash for entry: "+entry.Name, err)
		}
	}
	return buf.Bytes(), nil
}

// DeserializeTreeObject parses a Vec-formatted byte slice into a TreeObject.
func DeserializeTreeObject(data []byte) (*TreeObject, error) {
	if data == nil {
		return nil, ObjectError("nil data", nil)
	}
	tree := NewTreeObject()
	if len(data) == 0 {
		return tree, nil
	}
	pos := 0
	for pos < len(data) {
		spaceIdx := bytes.IndexByte(data[pos:], ' ')
		if spaceIdx == -1 {
			return nil, ObjectError("invalid tree entry: missing space", nil)
		}
		modeStr := string(data[pos : pos+spaceIdx])
		pos += spaceIdx + 1
		nullIdx := bytes.IndexByte(data[pos:], '\x00')
		if nullIdx == -1 {
			return nil, ObjectError("invalid tree entry: missing null byte", nil)
		}
		name := string(data[pos : pos+nullIdx])
		if name == "" {
			return nil, ObjectError("invalid tree entry: empty name", nil)
		}
		pos += nullIdx + 1
		if pos+32 > len(data) {
			return nil, ObjectError("invalid tree entry: incomplete hash for "+name, nil)
		}
		hashBytes := data[pos : pos+32]
		pos += 32
		mode, err := strconv.ParseInt(modeStr, 8, 32)
		if err != nil {
			return nil, ObjectError("invalid mode for entry: "+name, err)
		}
		if !ValidModes[int32(mode)] {
			return nil, ObjectError("unsupported mode for entry: "+name, nil)
		}
		var entryType string
		switch mode {
		case ModeFileRegular, ModeFileExecutable:
			entryType = "blob"
		case ModeTree:
			entryType = "tree"
		case ModeSymlink:
			entryType = "symlink"
		}
		tree.Entries = append(tree.Entries, TreeEntry{
			Mode: int32(mode),
			Name: name,
			Hash: hex.EncodeToString(hashBytes),
			Type: entryType,
		})
	}
	return tree, nil
}

// CalculateID calculates the SHA-256 hash of the TreeObject's serialized content.
func (t *TreeObject) CalculateID() (string, error) {
	if t == nil {
		return "", ObjectError("nil TreeObject", nil)
	}
	data, err := t.Serialize()
	if err != nil {
		return "", ObjectError("failed to serialize tree", err)
	}
	return HashBytes("tree", data), nil
}

// CreateTree creates a tree object from a slice of TreeEntry objects using the Repository context.
func (repo *Repository) CreateTree(entries []TreeEntry) (string, error) {
	if repo == nil {
		return "", ObjectError("nil repository", nil)
	}
	for _, entry := range entries {
		if !ValidModes[entry.Mode] {
			return "", ObjectError("invalid mode for entry: "+entry.Name, nil)
		}
		if len(entry.Hash) != 64 || !IsValidHex(entry.Hash) {
			return "", ObjectError("invalid hash for entry: "+entry.Name, nil)
		}
		if !isValidEntryType(entry.Type, entry.Mode) {
			return "", ObjectError("mismatched type and mode for entry: "+entry.Name, nil)
		}
	}
	tree := &TreeObject{Entries: entries}
	data, err := tree.Serialize()
	if err != nil {
		return "", ObjectError("failed to serialize tree", err)
	}
	hash, err := repo.WriteObject("tree", data)
	if err != nil {
		return "", ObjectError("failed to write tree", err)
	}
	tree.TreeID = hash
	return hash, nil
}

// CreateTree creates a tree object from a slice of TreeEntry objects using the repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateTree(repoRoot string, entries []TreeEntry) (string, error) {
	if repoRoot == "" {
		return "", RepositoryError("empty repository path provided", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.CreateTree(entries)
}

// GetTree retrieves and deserializes a TreeObject from disk using Repository context.
func (repo *Repository) GetTree(hash string) (*TreeObject, error) {
	if repo == nil {
		return nil, ObjectError("nil repository", nil)
	}
	if hash == "" {
		return nil, ObjectError("empty tree hash", nil)
	}
	if len(hash) != 64 || !IsValidHex(hash) {
		return nil, ObjectError("invalid tree hash", nil)
	}
	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, "tree "+hash[:8])
		}
		return nil, ObjectError("failed to read tree", err)
	}
	if objectType != "tree" {
		return nil, ObjectError("object is not a tree, but a "+objectType, nil)
	}
	tree, err := DeserializeTreeObject(data)
	if err != nil {
		return nil, ObjectError("failed to deserialize tree", err)
	}
	tree.TreeID = hash
	return tree, nil
}

// GetTree retrieves and deserializes a TreeObject from disk using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func GetTree(repoRoot string, hash string) (*TreeObject, error) {
	if repoRoot == "" {
		return nil, RepositoryError("empty repository path provided", nil)
	}
	if hash == "" {
		return nil, ObjectError("empty tree hash", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.GetTree(hash)
}

// CollectTreeEntries recursively collects all blob and symlink entries from a tree and subtrees.
func CollectTreeEntries(repoRoot string, tree *TreeObject, prefix string, entries map[string]TreeEntry) error {
	if repoRoot == "" {
		return RepositoryError("empty repository path provided", nil)
	}
	if tree == nil {
		return ObjectError("nil tree object for path: "+prefix, nil)
	}
	for _, entry := range tree.Entries {
		if !isValidEntryType(entry.Type, entry.Mode) {
			return ObjectError("invalid entry type or mode for: "+entry.Name, nil)
		}
		if !ValidModes[entry.Mode] {
			return ObjectError("invalid mode for: "+entry.Name, nil)
		}
		entryPath := filepath.Join(prefix, entry.Name)
		entries[entryPath] = entry
		if entry.Type == "tree" {
			subTree, err := GetTree(repoRoot, entry.Hash)
			if err != nil {
				return ObjectError("failed to get subtree: "+entryPath, err)
			}
			if err := CollectTreeEntries(repoRoot, subTree, entryPath, entries); err != nil {
				return ObjectError("failed to process subtree: "+entryPath, err)
			}
		}
	}
	return nil
}

// BuildTreeRecursively builds a tree hierarchy from a map of paths to entries.
func (repo *Repository) BuildTreeRecursively(dirPath string, treeMap map[string][]TreeEntry) ([]TreeEntry, error) {
	if repo == nil {
		return nil, ObjectError("nil repository", nil)
	}
	entries := treeMap[dirPath]
	directories := make(map[string]struct{}, 10)
	for path := range treeMap {
		if path == dirPath {
			continue
		}
		if dirPath == "" || strings.HasPrefix(path, dirPath+"/") {
			parts := strings.Split(strings.TrimPrefix(path, dirPath+"/"), "/")
			if len(parts) == 1 && parts[0] != "" {
				directories[parts[0]] = struct{}{}
			}
		}
	}
	for dirName := range directories {
		childPath := filepath.Join(dirPath, dirName)
		childEntries, err := repo.BuildTreeRecursively(childPath, treeMap)
		if err != nil {
			return nil, ObjectError("failed to build tree for: "+childPath, err)
		}
		treeHash, err := repo.CreateTree(childEntries)
		if err != nil {
			return nil, ObjectError("failed to create tree for: "+childPath, err)
		}
		entries = append(entries, TreeEntry{
			Mode: ModeTree,
			Name: dirName,
			Hash: treeHash,
			Type: "tree",
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// DiffTrees compares two trees and returns added, modified, and deleted entries.
func (repo *Repository) DiffTrees(tree1, tree2 *TreeObject) (added, modified, deleted []TreeEntry, err error) {
	if repo == nil {
		return nil, nil, nil, ObjectError("nil repository", nil)
	}
	if tree1 == nil || tree2 == nil {
		return nil, nil, nil, ObjectError("nil tree object", nil)
	}
	entries1 := make(map[string]TreeEntry, len(tree1.Entries)*2)
	entries2 := make(map[string]TreeEntry, len(tree2.Entries)*2)
	if err := CollectTreeEntries(repo.Root, tree1, "", entries1); err != nil {
		return nil, nil, nil, ObjectError("failed to collect entries for tree1", err)
	}
	if err := CollectTreeEntries(repo.Root, tree2, "", entries2); err != nil {
		return nil, nil, nil, ObjectError("failed to collect entries for tree2", err)
	}
	for path, entry := range entries2 {
		if oldEntry, exists := entries1[path]; !exists {
			added = append(added, entry)
		} else if oldEntry.Hash != entry.Hash || oldEntry.Mode != entry.Mode {
			modified = append(modified, entry)
		}
	}
	for path, entry := range entries1 {
		if _, exists := entries2[path]; !exists {
			deleted = append(deleted, entry)
		}
	}
	return added, modified, deleted, nil
}

// isValidEntryType checks if the entry type matches the mode.
func isValidEntryType(entryType string, mode int32) bool {
	return (entryType == "blob" && (mode == ModeFileRegular || mode == ModeFileExecutable)) ||
		(entryType == "tree" && mode == ModeTree) ||
		(entryType == "symlink" && mode == ModeSymlink)
}
