package core

// CreateBlob creates a new blob object from content using the Repository context.
// Returns the SHA-256 hash of the blob.
func (repo *Repository) CreateBlob(content []byte) (string, error) {
	if content == nil {
		return "", ObjectError("nil content provided for blob", nil)
	}
	hash, err := repo.WriteObject("blob", content)
	if err != nil {
		return "", ObjectError("failed to create blob", err)
	}
	return hash, nil
}

// CreateBlob creates a new blob object from content using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func CreateBlob(repoRoot string, content []byte) (string, error) {
	if repoRoot == "" {
		return "", RepositoryError("empty repository path provided", nil)
	}
	if content == nil {
		return "", ObjectError("nil content provided for blob", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.CreateBlob(content)
}

// GetBlob retrieves a blob object by its hash using the Repository context.
func (repo *Repository) GetBlob(hash string) ([]byte, error) {
	if len(hash) != 64 || !IsValidHex(hash) {
		return nil, ObjectError("invalid blob hash format", nil)
	}
	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		if IsErrNotFound(err) {
			return nil, NotFoundError(ErrCategoryObject, "blob "+hash[:8])
		}
		return nil, ObjectError("failed to read blob", err)
	}
	if objectType != "blob" {
		return nil, ObjectError("object is not a blob, but a "+objectType, nil)
	}
	return data, nil
}

// GetBlob retrieves a blob object by its hash using repository path.
// This is a convenience function for code that doesn't have a Repository context.
func GetBlob(repoRoot string, hash string) ([]byte, error) {
	if repoRoot == "" {
		return nil, RepositoryError("empty repository path provided", nil)
	}
	if len(hash) != 64 || !IsValidHex(hash) {
		return nil, ObjectError("invalid blob hash format", nil)
	}
	repo := NewRepository(repoRoot)
	return repo.GetBlob(hash)
}
