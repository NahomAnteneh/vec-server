package objects

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Commit represents a commit object
type Commit struct {
	Hash           string
	TreeHash       string
	Parents        []string
	Author         string
	AuthorEmail    string
	AuthorDate     time.Time
	Committer      string
	CommitterEmail string
	CommitterDate  time.Time
	Message        string
}

// NewCommit creates a new commit object
func NewCommit(treeHash string, parents []string, author, authorEmail string, committer, committerEmail string, message string) *Commit {
	now := time.Now()

	commit := &Commit{
		TreeHash:       treeHash,
		Parents:        parents,
		Author:         author,
		AuthorEmail:    authorEmail,
		AuthorDate:     now,
		Committer:      committer,
		CommitterEmail: committerEmail,
		CommitterDate:  now,
		Message:        message,
	}
	commit.calculateHash()
	return commit
}

// GetType returns the object type
func (c *Commit) GetType() ObjectType {
	return ObjectTypeCommit
}

// GetHash returns the commit hash
func (c *Commit) GetHash() string {
	if c.Hash == "" {
		c.calculateHash()
	}
	return c.Hash
}

// calculateHash calculates the SHA-256 hash of the commit
func (c *Commit) calculateHash() {
	content, _ := c.serializeContent()
	header := fmt.Sprintf("commit %d\x00", len(content))

	h := sha256.New()
	h.Write([]byte(header))
	h.Write(content)
	c.Hash = hex.EncodeToString(h.Sum(nil))
}

// serializeContent returns the content of the commit without the header
func (c *Commit) serializeContent() ([]byte, error) {
	var buf bytes.Buffer

	// Write tree reference
	fmt.Fprintf(&buf, "tree %s\n", c.TreeHash)

	// Write parent references
	for _, parent := range c.Parents {
		fmt.Fprintf(&buf, "parent %s\n", parent)
	}

	// Write author info with timestamp in format: "name <email> timestamp timezone"
	// Using Unix timestamp and +0000 timezone for simplicity
	fmt.Fprintf(&buf, "author %s <%s> %d +0000\n",
		c.Author, c.AuthorEmail, c.AuthorDate.Unix())

	// Write committer info
	fmt.Fprintf(&buf, "committer %s <%s> %d +0000\n",
		c.Committer, c.CommitterEmail, c.CommitterDate.Unix())

	// Empty line followed by message
	fmt.Fprintf(&buf, "\n%s", c.Message)

	return buf.Bytes(), nil
}

// Serialize serializes the commit into bytes with header
func (c *Commit) Serialize() ([]byte, error) {
	content, err := c.serializeContent()
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf("commit %d\x00", len(content))
	result := make([]byte, len(header)+len(content))
	copy(result, []byte(header))
	copy(result[len(header):], content)

	return result, nil
}

// Parse parses a commit object from raw content
func (c *Commit) Parse(data []byte) error {
	// Find the null byte that separates header from content
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		return fmt.Errorf("invalid commit format: no null byte found")
	}

	// Parse header
	header := string(data[:nullIndex])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "commit" {
		return fmt.Errorf("invalid commit header: %s", header)
	}

	// Parse content
	content := data[nullIndex+1:]
	lines := bytes.Split(content, []byte("\n"))

	var messageStartIndex int

	// Parse metadata lines
	for i, line := range lines {
		// Empty line indicates start of commit message
		if len(line) == 0 {
			messageStartIndex = i + 1
			break
		}

		parts := bytes.SplitN(line, []byte(" "), 2)
		if len(parts) != 2 {
			continue
		}

		key := string(parts[0])
		value := string(parts[1])

		switch key {
		case "tree":
			c.TreeHash = value
		case "parent":
			c.Parents = append(c.Parents, value)
		case "author":
			// Parse author info in format "Name <email> timestamp timezone"
			c.parsePersonInfo(value, true)
		case "committer":
			// Parse committer info
			c.parsePersonInfo(value, false)
		}
	}

	// Extract commit message
	if messageStartIndex > 0 && messageStartIndex < len(lines) {
		c.Message = string(bytes.Join(lines[messageStartIndex:], []byte("\n")))
	}

	// Calculate hash
	c.calculateHash()

	return nil
}

// parsePersonInfo parses person information (author or committer)
func (c *Commit) parsePersonInfo(info string, isAuthor bool) {
	// Parse: "Name <email> timestamp timezone"
	emailStart := strings.LastIndex(info, "<")
	emailEnd := strings.LastIndex(info, ">")
	timestampStart := emailEnd + 2

	if emailStart > 0 && emailEnd > emailStart {
		name := strings.TrimSpace(info[:emailStart])
		email := info[emailStart+1 : emailEnd]
		timestampStr := strings.TrimSpace(info[timestampStart:])

		// Parse timestamp
		var timestamp int64
		var timezone string
		fmt.Sscanf(timestampStr, "%d %s", &timestamp, &timezone)

		if isAuthor {
			c.Author = name
			c.AuthorEmail = email
			c.AuthorDate = time.Unix(timestamp, 0)
		} else {
			c.Committer = name
			c.CommitterEmail = email
			c.CommitterDate = time.Unix(timestamp, 0)
		}
	}
}

// Validate checks if the commit is valid
func (c *Commit) Validate() error {
	// Check required fields
	if c.TreeHash == "" {
		return fmt.Errorf("commit must have a tree reference")
	}

	if c.Author == "" || c.AuthorEmail == "" {
		return fmt.Errorf("commit must have author information")
	}

	if c.Committer == "" || c.CommitterEmail == "" {
		return fmt.Errorf("commit must have committer information")
	}

	// Validate hash integrity
	oldHash := c.Hash
	c.calculateHash()
	if oldHash != "" && oldHash != c.Hash {
		return fmt.Errorf("commit hash mismatch: expected %s, got %s", oldHash, c.Hash)
	}

	return nil
}

// Store stores the commit in the object storage
func (c *Commit) Store(storage *Storage) error {
	if err := c.Validate(); err != nil {
		return err
	}

	content, err := c.serializeContent()
	if err != nil {
		return err
	}

	obj := &Object{
		Hash:    c.Hash,
		Type:    ObjectTypeCommit,
		Content: content,
	}

	return storage.StoreObject(obj)
}

// LoadCommit loads a commit from storage by hash
func LoadCommit(storage *Storage, hash string) (*Commit, error) {
	// Get object from storage
	obj, err := storage.GetObject(hash)
	if err != nil {
		return nil, err
	}

	// Check that it's a commit
	if obj.Type != ObjectTypeCommit {
		return nil, fmt.Errorf("object %s is not a commit", hash)
	}

	// Create and parse commit
	commit := &Commit{}
	if err := commit.Parse(append([]byte("commit "+fmt.Sprint(len(obj.Content))+"\x00"), obj.Content...)); err != nil {
		return nil, err
	}

	return commit, nil
}

// GetMessage returns the commit message
func (c *Commit) GetMessage() string {
	return c.Message
}

// GetAuthor returns the commit author
func (c *Commit) GetAuthor() string {
	return fmt.Sprintf("%s <%s>", c.Author, c.AuthorEmail)
}

// IsParent checks if the given hash is a parent of this commit
func (c *Commit) IsParent(hash string) bool {
	for _, parent := range c.Parents {
		if parent == hash {
			return true
		}
	}
	return false
}
