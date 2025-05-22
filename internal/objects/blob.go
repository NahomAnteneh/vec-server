package objects

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
)

// Blob represents a binary blob object
type Blob struct {
	Hash    string
	Content []byte
	Path    string // Optional path for content type detection
}

// NewBlob creates a new blob from content
func NewBlob(content []byte) *Blob {
	b := &Blob{
		Content: content,
	}
	b.calculateHash()
	return b
}

// NewBlobWithPath creates a new blob from content with an associated file path
func NewBlobWithPath(content []byte, path string) *Blob {
	b := &Blob{
		Content: content,
		Path:    path,
	}
	b.calculateHash()
	return b
}

// GetType returns the object type
func (b *Blob) GetType() ObjectType {
	return ObjectTypeBlob
}

// GetContent returns the blob content
func (b *Blob) GetContent() []byte {
	return b.Content
}

// GetHash returns the SHA-256 hash of the blob
func (b *Blob) GetHash() string {
	if b.Hash == "" {
		b.calculateHash()
	}
	return b.Hash
}

// calculateHash calculates the SHA-256 hash of the blob with the header
func (b *Blob) calculateHash() {
	header := fmt.Sprintf("blob %d\x00", len(b.Content))
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(b.Content)
	b.Hash = hex.EncodeToString(h.Sum(nil))
}

// Serialize serializes the blob into bytes with header
func (b *Blob) Serialize() ([]byte, error) {
	header := fmt.Sprintf("blob %d\x00", len(b.Content))
	result := make([]byte, len(header)+len(b.Content))
	copy(result, []byte(header))
	copy(result[len(header):], b.Content)
	return result, nil
}

// DetectContentType attempts to detect the MIME type of the blob content
func (b *Blob) DetectContentType() string {
	// First try by content inspection
	contentType := http.DetectContentType(b.Content)

	// If it's a generic binary or text, try by extension if we have a path
	if (contentType == "application/octet-stream" || contentType == "text/plain") && b.Path != "" {
		// Try to get content type from file extension
		extType := mime.TypeByExtension(filepath.Ext(b.Path))
		if extType != "" {
			return extType
		}
	}

	return contentType
}

// Validate checks if the blob content is valid
func (b *Blob) Validate() error {
	// Basic validation - ensure we have content
	if len(b.Content) == 0 {
		return fmt.Errorf("blob cannot be empty")
	}

	// Verify hash integrity
	oldHash := b.Hash
	b.calculateHash()
	if oldHash != "" && oldHash != b.Hash {
		return fmt.Errorf("blob hash mismatch: expected %s, got %s", oldHash, b.Hash)
	}

	return nil
}

// Store stores the blob in the object storage
func (b *Blob) Store(storage *Storage) error {
	// Validate the blob first
	if err := b.Validate(); err != nil {
		return err
	}

	// Create object for storage
	obj := &Object{
		Hash:    b.Hash,
		Type:    ObjectTypeBlob,
		Content: b.Content,
	}

	// Store the object
	return storage.StoreObject(obj)
}

// LoadBlob loads a blob from storage by hash
func LoadBlob(storage *Storage, hash string) (*Blob, error) {
	// Get object from storage
	obj, err := storage.GetObject(hash)
	if err != nil {
		return nil, err
	}

	// Check that it's a blob
	if obj.Type != ObjectTypeBlob {
		return nil, fmt.Errorf("object %s is not a blob", hash)
	}

	// Create and return blob
	blob := &Blob{
		Hash:    hash,
		Content: obj.Content,
	}

	return blob, nil
}

// LoadBlobFromFile loads a blob from a file
func LoadBlobFromFile(filePath string) (*Blob, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file size for pre-allocating buffer
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Read file content
	content := make([]byte, info.Size())
	if _, err := io.ReadFull(file, content); err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}

	// Create a new blob with the file content and path
	blob := NewBlobWithPath(content, filePath)

	return blob, nil
}

// GetCompressedContent returns the zlib-compressed content of the blob
func (b *Blob) GetCompressedContent() ([]byte, error) {
	var buf bytes.Buffer

	// Create a zlib writer
	zlibWriter := zlib.NewWriter(&buf)

	// Write the serialized content
	data, err := b.Serialize()
	if err != nil {
		return nil, err
	}

	if _, err := zlibWriter.Write(data); err != nil {
		return nil, err
	}

	// Close the writer to flush any pending data
	if err := zlibWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
