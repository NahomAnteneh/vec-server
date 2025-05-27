package core

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"time"
)

// Commit represents a commit object in the repository.
type Commit struct {
	CommitID  string    // Hash of the serialized commit data
	Tree      string    // Hash of the tree object
	Parents   []string  // Hashes of parent commits
	Author    string    // Author name and email (e.g., "Author Name <author@example.com>")
	Committer string    // Committer name and email
	Message   string    // Commit message
	Timestamp time.Time // Commit timestamp
}

// serialize serializes the commit object into a byte slice, excluding CommitID.
func (c *Commit) serialize() ([]byte, error) {
	if c == nil {
		return nil, ObjectError("nil commit", nil)
	}
	if len(c.Tree) != 64 || !IsValidHex(c.Tree) {
		return nil, ObjectError("invalid tree hash", nil)
	}
	for _, parent := range c.Parents {
		if len(parent) != 64 || !IsValidHex(parent) {
			return nil, ObjectError("invalid parent hash: "+parent[:8], nil)
		}
	}
	if !isValidAuthorFormat(c.Author) {
		return nil, ObjectError("invalid author format", nil)
	}
	if !isValidAuthorFormat(c.Committer) {
		return nil, ObjectError("invalid committer format", nil)
	}

	var buf bytes.Buffer
	if err := writeLengthPrefixedString(&buf, c.Tree); err != nil {
		return nil, ObjectError("failed to write tree", err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(c.Parents))); err != nil {
		return nil, ObjectError("failed to write parent count", err)
	}
	for _, parent := range c.Parents {
		if err := writeLengthPrefixedString(&buf, parent); err != nil {
			return nil, ObjectError("failed to write parent", err)
		}
	}
	if err := writeLengthPrefixedString(&buf, c.Author); err != nil {
		return nil, ObjectError("failed to write author", err)
	}
	if err := writeLengthPrefixedString(&buf, c.Committer); err != nil {
		return nil, ObjectError("failed to write committer", err)
	}
	if err := binary.Write(&buf, binary.LittleEndian, c.Timestamp.Unix()); err != nil {
		return nil, ObjectError("failed to write timestamp", err)
	}
	if err := writeLengthPrefixedString(&buf, c.Message); err != nil {
		return nil, ObjectError("failed to write message", err)
	}
	return buf.Bytes(), nil
}

// deserializeCommit deserializes a byte slice into a Commit object.
func deserializeCommit(data []byte) (*Commit, error) {
	if data == nil {
		return nil, ObjectError("nil data", nil)
	}
	buf := bytes.NewReader(data)
	commit := &Commit{}

	var err error
	commit.Tree, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, ObjectError("failed to read tree", err)
	}
	if len(commit.Tree) != 64 || !IsValidHex(commit.Tree) {
		return nil, ObjectError("invalid tree hash", nil)
	}

	var parentCount uint32
	if err := binary.Read(buf, binary.LittleEndian, &parentCount); err != nil {
		return nil, ObjectError("failed to read parent count", err)
	}
	commit.Parents = make([]string, parentCount)
	for i := uint32(0); i < parentCount; i++ {
		commit.Parents[i], err = readLengthPrefixedString(buf)
		if err != nil {
			return nil, ObjectError("failed to read parent", err)
		}
		if len(commit.Parents[i]) != 64 || !IsValidHex(commit.Parents[i]) {
			return nil, ObjectError("invalid parent hash", nil)
		}
	}

	commit.Author, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, ObjectError("failed to read author", err)
	}
	commit.Committer, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, ObjectError("failed to read committer", err)
	}
	if !isValidAuthorFormat(commit.Author) {
		return nil, ObjectError("invalid author format", nil)
	}
	if !isValidAuthorFormat(commit.Committer) {
		return nil, ObjectError("invalid committer format", nil)
	}

	var timestamp int64
	if err := binary.Read(buf, binary.LittleEndian, &timestamp); err != nil {
		return nil, ObjectError("failed to read timestamp", err)
	}
	commit.Timestamp = time.Unix(timestamp, 0)

	commit.Message, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, ObjectError("failed to read message", err)
	}
	return commit, nil
}

// CreateCommit creates a new commit object using the Repository context.
func (repo *Repository) CreateCommit(treeHash string, parentHashes []string, author, committer, message string, timestamp time.Time) (string, error) {
	if len(treeHash) != 64 || !IsValidHex(treeHash) {
		return "", ObjectError("invalid tree hash", nil)
	}
	for _, parent := range parentHashes {
		if len(parent) != 64 || !IsValidHex(parent) {
			return "", ObjectError("invalid parent hash: "+parent[:8], nil)
		}
	}
	if author == "" {
		return "", ObjectError("author cannot be empty", nil)
	}
	if !isValidAuthorFormat(author) {
		return "", ObjectError("invalid author format", nil)
	}
	if committer == "" {
		committer = author
	}
	if !isValidAuthorFormat(committer) {
		return "", ObjectError("invalid committer format", nil)
	}
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	commit := &Commit{
		Tree:      treeHash,
		Parents:   parentHashes,
		Author:    author,
		Committer: committer,
		Message:   message,
		Timestamp: timestamp,
	}

	data, err := commit.serialize()
	if err != nil {
		return "", ObjectError("failed to serialize commit", err)
	}
	hash, err := repo.WriteObject("commit", data)
	if err != nil {
		return "", ObjectError("failed to write commit", err)
	}
	commit.CommitID = hash
	return hash, nil
}

// CreateCommit creates a new commit object using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateCommit(repoRoot string, treeHash string, parentHashes []string, author, committer, message string, timestamp time.Time) (string, error) {
	if repoRoot == "" {
		return "", RepositoryError("empty repository path provided", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.CreateCommit(treeHash, parentHashes, author, committer, message, timestamp)
}

// GetCommit reads a commit object from disk using Repository context.
func (repo *Repository) GetCommit(hash string) (*Commit, error) {
	if len(hash) != 64 || !IsValidHex(hash) {
		return nil, ObjectError("invalid commit hash", nil)
	}
	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, "commit "+hash[:8])
		}
		return nil, ObjectError("failed to read commit", err)
	}
	if objectType != "commit" {
		return nil, ObjectError("object is not a commit, but a "+objectType, nil)
	}

	commit, err := deserializeCommit(data)
	if err != nil {
		return nil, ObjectError("failed to deserialize commit", err)
	}
	commit.CommitID = hash
	return commit, nil
}

// GetCommit reads a commit object from disk using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func GetCommit(repoRoot string, hash string) (*Commit, error) {
	if repoRoot == "" {
		return nil, RepositoryError("empty repository path provided", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.GetCommit(hash)
}

// GetCommitTime returns the commit time as a time.Time object.
func (c *Commit) GetCommitTime() time.Time {
	return c.Timestamp
}

// writeLengthPrefixedString writes a length-prefixed string to the buffer.
func writeLengthPrefixedString(buf *bytes.Buffer, s string) error {
	if buf == nil {
		return ObjectError("nil buffer", nil)
	}
	strBytes := []byte(s)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(strBytes))); err != nil {
		return ObjectError("failed to write string length", err)
	}
	if _, err := buf.Write(strBytes); err != nil {
		return ObjectError("failed to write string data", err)
	}
	return nil
}

// readLengthPrefixedString reads a length-prefixed string from the buffer.
func readLengthPrefixedString(buf *bytes.Reader) (string, error) {
	if buf == nil {
		return "", ObjectError("nil buffer", nil)
	}
	var length uint32
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		return "", ObjectError("failed to read string length", err)
	}
	if length > uint32(buf.Size()) {
		return "", ObjectError("string length exceeds buffer size", nil)
	}
	strBytes := make([]byte, length)
	if _, err := buf.Read(strBytes); err != nil {
		return "", ObjectError("failed to read string data", err)
	}
	return string(strBytes), nil
}

// isValidAuthorFormat checks if the author/committer string matches "Name <email>" format.
func isValidAuthorFormat(s string) bool {
	if s == "" {
		return false
	}
	re := regexp.MustCompile(`^[^<]+ <[^>]+@[^>]+>$`)
	return re.MatchString(s)
}
