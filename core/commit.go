package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Commit represents a commit object in the repository.
type Commit struct {
	CommitID  string   // Hash of the serialized commit data (calculated, not stored)
	Tree      string   // Hash of the tree object
	Parents   []string // Hashes of parent commits
	Author    string   // Author name and email (e.g., "Author Name <author@example.com>")
	Committer string   // Committer name and email (e.g., "Committer Name <committer@example.com>")
	Message   string   // Commit message
	Timestamp int64    // Commit timestamp (Unix time)
}

// serialize serializes the commit object into a byte slice, excluding CommitID.
func (c *Commit) serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Tree (length-prefixed string)
	if err := writeLengthPrefixedString(&buf, c.Tree); err != nil {
		return nil, fmt.Errorf("failed to write tree: %w", err)
	}

	// Parents (count + length-prefixed strings)
	parentCount := uint32(len(c.Parents))
	if err := binary.Write(&buf, binary.LittleEndian, parentCount); err != nil {
		return nil, fmt.Errorf("failed to write parent count: %w", err)
	}
	for _, parent := range c.Parents {
		if err := writeLengthPrefixedString(&buf, parent); err != nil {
			return nil, fmt.Errorf("failed to write parent: %w", err)
		}
	}

	// Author (length-prefixed string)
	if err := writeLengthPrefixedString(&buf, c.Author); err != nil {
		return nil, fmt.Errorf("failed to write author: %w", err)
	}

	// Committer (length-prefixed string)
	if err := writeLengthPrefixedString(&buf, c.Committer); err != nil {
		return nil, fmt.Errorf("failed to write committer: %w", err)
	}

	// Timestamp (int64)
	if err := binary.Write(&buf, binary.LittleEndian, c.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to write timestamp: %w", err)
	}

	// Message (length-prefixed string)
	if err := writeLengthPrefixedString(&buf, c.Message); err != nil {
		return nil, fmt.Errorf("failed to write message: %w", err)
	}

	return buf.Bytes(), nil
}

// deserializeCommit deserializes a byte slice into a Commit object.
func deserializeCommit(data []byte) (*Commit, error) {
	buf := bytes.NewReader(data)
	commit := &Commit{}

	// Tree
	var err error
	commit.Tree, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read tree: %w", err)
	}

	// Parents
	var parentCount uint32
	if err := binary.Read(buf, binary.LittleEndian, &parentCount); err != nil {
		return nil, fmt.Errorf("failed to read parent count: %w", err)
	}
	commit.Parents = make([]string, parentCount)
	for i := uint32(0); i < parentCount; i++ {
		commit.Parents[i], err = readLengthPrefixedString(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read parent: %w", err)
		}
	}

	// Author
	commit.Author, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read author: %w", err)
	}

	// Committer
	commit.Committer, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read committer: %w", err)
	}

	// Timestamp
	if err := binary.Read(buf, binary.LittleEndian, &commit.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %w", err)
	}

	// Message
	commit.Message, err = readLengthPrefixedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	return commit, nil
}

// CreateCommit creates a new commit object using the Repository context.
func (repo *Repository) CreateCommit(treeHash string, parentHashes []string, author, committer, message string, timestamp int64) (string, error) {
	// Validate inputs
	if treeHash == "" {
		return "", ObjectError("tree hash cannot be empty", nil)
	}
	if author == "" {
		return "", ObjectError("author cannot be empty", nil)
	}
	if committer == "" {
		committer = author // Default committer to author if empty
	}
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}

	commit := &Commit{
		Tree:      treeHash,
		Parents:   parentHashes,
		Author:    author,
		Committer: committer,
		Message:   message,
		Timestamp: timestamp,
	}

	// Serialize the commit specific data
	commitData, err := commit.serialize()
	if err != nil {
		return "", ObjectError(fmt.Sprintf("failed to serialize commit: %s", err.Error()), err)
	}

	// Use WriteObject to handle hashing, header formatting, and writing.
	hash, err := repo.WriteObject("commit", commitData)
	if err != nil {
		return "", ObjectError(fmt.Sprintf("failed to write commit object: %s", err.Error()), err)
	}

	return hash, nil
}

// CreateCommit creates a new commit object using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateCommit(repoRoot string, treeHash string, parentHashes []string, author, committer, message string, timestamp int64) (string, error) {
	// Create a temporary Repository object
	repo := NewRepository(repoRoot)
	return repo.CreateCommit(treeHash, parentHashes, author, committer, message, timestamp)
}

// GetCommit reads a commit object from disk using Repository context.
func (repo *Repository) GetCommit(hash string) (*Commit, error) {
	objectType, commitData, err := repo.ReadObject(hash)
	if err != nil {
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, fmt.Sprintf("commit %s", hash))
		}
		return nil, ObjectError(fmt.Sprintf("failed to read commit object %s: %s", hash, err.Error()), err)
	}

	if objectType != "commit" {
		return nil, ObjectError(fmt.Sprintf("object %s is not a commit, but a %s", hash, objectType), nil)
	}

	commit, err := deserializeCommit(commitData)
	if err != nil {
		return nil, ObjectError(fmt.Sprintf("failed to deserialize commit %s: %s", hash, err.Error()), err)
	}

	commit.CommitID = hash // Assign the hash to the commit object
	return commit, nil
}

// GetCommit reads a commit object from disk using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func GetCommit(repoRoot string, hash string) (*Commit, error) {
	// Create a temporary Repository object
	repo := NewRepository(repoRoot)
	return repo.GetCommit(hash)
}

// GetCommitTime returns the commit time as a time.Time object.
func (c *Commit) GetCommitTime() time.Time {
	return time.Unix(c.Timestamp, 0)
}

// writeLengthPrefixedString writes a length-prefixed string to the buffer.
func writeLengthPrefixedString(buf *bytes.Buffer, s string) error {
	strBytes := []byte(s)
	length := uint32(len(strBytes))
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return err
	}
	if _, err := buf.Write(strBytes); err != nil {
		return err
	}
	return nil
}

// readLengthPrefixedString reads a length-prefixed string from the buffer.
func readLengthPrefixedString(buf *bytes.Reader) (string, error) {
	var length uint32
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	strBytes := make([]byte, length)
	if _, err := buf.Read(strBytes); err != nil {
		return "", err
	}
	return string(strBytes), nil
}
