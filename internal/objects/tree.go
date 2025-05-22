package objects

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// FileMode represents file mode (regular, executable, directory, etc.)
type FileMode uint32

const (
	// ModeRegular represents a regular file
	ModeRegular FileMode = 0100644
	// ModeExecutable represents an executable file
	ModeExecutable FileMode = 0100755
	// ModeDirectory represents a directory
	ModeDirectory FileMode = 0040000
	// ModeSymlink represents a symbolic link
	ModeSymlink FileMode = 0120000
)

// String returns the octal string representation of the file mode
func (m FileMode) String() string {
	return fmt.Sprintf("%06o", m)
}

// TreeEntry represents a single entry in a tree object
type TreeEntry struct {
	Mode FileMode
	Name string
	Hash string
}

// Tree represents a tree object (directory structure)
type Tree struct {
	Hash    string
	Entries []TreeEntry
}

// NewTree creates a new empty tree
func NewTree() *Tree {
	return &Tree{
		Entries: make([]TreeEntry, 0),
	}
}

// AddEntry adds an entry to the tree
func (t *Tree) AddEntry(mode FileMode, name, hash string) {
	t.Entries = append(t.Entries, TreeEntry{
		Mode: mode,
		Name: name,
		Hash: hash,
	})
	t.Hash = "" // Reset hash as tree content changed
}

// GetEntry finds an entry by name
func (t *Tree) GetEntry(name string) (TreeEntry, bool) {
	for _, entry := range t.Entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return TreeEntry{}, false
}

// GetType returns the object type
func (t *Tree) GetType() ObjectType {
	return ObjectTypeTree
}

// GetHash returns the SHA-256 hash of the tree
func (t *Tree) GetHash() string {
	if t.Hash == "" {
		t.calculateHash()
	}
	return t.Hash
}

// calculateHash calculates the SHA-256 hash of the tree with the header
func (t *Tree) calculateHash() {
	// Sort entries in canonical order before hashing
	t.sortEntries()

	content, _ := t.serializeContent()
	header := fmt.Sprintf("tree %d\x00", len(content))

	h := sha256.New()
	h.Write([]byte(header))
	h.Write(content)
	t.Hash = hex.EncodeToString(h.Sum(nil))
}

// sortEntries sorts the entries in canonical order (directories first, then by name)
func (t *Tree) sortEntries() {
	sort.Slice(t.Entries, func(i, j int) bool {
		// If one is a directory and the other isn't, directory comes first
		iIsDir := t.Entries[i].Mode == ModeDirectory
		jIsDir := t.Entries[j].Mode == ModeDirectory

		if iIsDir != jIsDir {
			return iIsDir
		}

		// Otherwise sort by name
		return t.Entries[i].Name < t.Entries[j].Name
	})
}

// serializeContent returns the content of the tree without the header
func (t *Tree) serializeContent() ([]byte, error) {
	var buf bytes.Buffer

	// Sort entries for consistent hashing
	t.sortEntries()

	// Write each entry
	for _, entry := range t.Entries {
		// Format: "mode name\0hash"
		fmt.Fprintf(&buf, "%s %s\x00", entry.Mode.String(), entry.Name)

		// Write hash as binary (not as a hex string)
		hashBytes, err := hex.DecodeString(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hash in tree entry: %s", err)
		}
		buf.Write(hashBytes)
	}

	return buf.Bytes(), nil
}

// Serialize serializes the tree into bytes with header
func (t *Tree) Serialize() ([]byte, error) {
	content, err := t.serializeContent()
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf("tree %d\x00", len(content))
	result := make([]byte, len(header)+len(content))
	copy(result, []byte(header))
	copy(result[len(header):], content)

	return result, nil
}

// Parse parses a tree object from raw data
func (t *Tree) Parse(data []byte) error {
	// Find the null byte that separates header from content
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		return fmt.Errorf("invalid tree format: no null byte found")
	}

	// Parse header
	header := string(data[:nullIndex])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "tree" {
		return fmt.Errorf("invalid tree header: %s", header)
	}

	// Parse content
	content := data[nullIndex+1:]
	t.Entries = make([]TreeEntry, 0)

	// Parse entries
	for len(content) > 0 {
		// Find the space that separates mode from name
		spaceIndex := bytes.IndexByte(content, ' ')
		if spaceIndex == -1 {
			return fmt.Errorf("invalid tree entry: no space found")
		}

		// Parse mode
		modeStr := string(content[:spaceIndex])
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid tree entry mode: %s", err)
		}

		// Get name and hash part
		nameAndHash := content[spaceIndex+1:]

		// Find the null byte that separates name from hash
		nullIndex := bytes.IndexByte(nameAndHash, 0)
		if nullIndex == -1 {
			return fmt.Errorf("invalid tree entry: no null byte found")
		}

		// Parse name
		name := string(nameAndHash[:nullIndex])

		// Parse hash (as hex string)
		hash := hex.EncodeToString(nameAndHash[nullIndex+1 : nullIndex+33])

		// Add entry
		t.AddEntry(FileMode(mode), name, hash)

		// Move to next entry
		content = nameAndHash[nullIndex+33:]
	}

	// Calculate hash
	t.calculateHash()

	return nil
}

// Validate checks if the tree is valid
func (t *Tree) Validate() error {
	// Check for duplicate names
	names := make(map[string]bool)
	for _, entry := range t.Entries {
		if entry.Name == "" {
			return fmt.Errorf("tree entry name cannot be empty")
		}

		if names[entry.Name] {
			return fmt.Errorf("duplicate entry name in tree: %s", entry.Name)
		}
		names[entry.Name] = true

		// Validate hash format
		if len(entry.Hash) != 64 || !IsValidHex(entry.Hash) {
			return fmt.Errorf("invalid hash in tree entry: %s", entry.Hash)
		}
	}

	// Validate hash integrity
	oldHash := t.Hash
	t.calculateHash()
	if oldHash != "" && oldHash != t.Hash {
		return fmt.Errorf("tree hash mismatch: expected %s, got %s", oldHash, t.Hash)
	}

	return nil
}

// Store stores the tree in the object storage
func (t *Tree) Store(storage *Storage) error {
	if err := t.Validate(); err != nil {
		return err
	}

	content, err := t.serializeContent()
	if err != nil {
		return err
	}

	obj := &Object{
		Hash:    t.Hash,
		Type:    ObjectTypeTree,
		Content: content,
	}

	return storage.StoreObject(obj)
}

// LoadTree loads a tree from storage by hash
func LoadTree(storage *Storage, hash string) (*Tree, error) {
	// Get object from storage
	obj, err := storage.GetObject(hash)
	if err != nil {
		return nil, err
	}

	// Check that it's a tree
	if obj.Type != ObjectTypeTree {
		return nil, fmt.Errorf("object %s is not a tree", hash)
	}

	// Create and parse tree
	tree := &Tree{}
	if err := tree.Parse(append([]byte("tree "+fmt.Sprint(len(obj.Content))+"\x00"), obj.Content...)); err != nil {
		return nil, err
	}

	return tree, nil
}

// GetEntryCount returns the number of entries in the tree
func (t *Tree) GetEntryCount() int {
	return len(t.Entries)
}

// RemoveEntry removes an entry by name
func (t *Tree) RemoveEntry(name string) bool {
	for i, entry := range t.Entries {
		if entry.Name == name {
			// Remove the entry and reset the hash
			t.Entries = append(t.Entries[:i], t.Entries[i+1:]...)
			t.Hash = ""
			return true
		}
	}
	return false
}

// IsEmpty checks if the tree has no entries
func (t *Tree) IsEmpty() bool {
	return len(t.Entries) == 0
}
