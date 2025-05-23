package objects

import (
	"github.com/NahomAnteneh/vec-server/core"
)

// CreateBlob creates a new blob object from content.
// Returns the SHA-256 hash of the blob.
func CreateBlob(repoRoot string, content []byte) (string, error) {
	if repoRoot == "" {
		return "", core.RepositoryError("empty repository path provided", nil)
	}
	if content == nil {
		return "", core.ObjectError("nil content provided for blob", nil)
	}

	repo := core.NewRepository(repoRoot)
	hash, err := repo.WriteObject("blob", content)
	if err != nil {
		return "", core.ObjectError("failed to create blob", err)
	}
	return hash, nil
}

// GetBlob retrieves a blob object by its hash.
func GetBlob(repoRoot string, hash string) ([]byte, error) {
	if repoRoot == "" {
		return nil, core.RepositoryError("empty repository path provided", nil)
	}
	if len(hash) != 64 || !core.IsValidHex(hash) {
		return nil, core.ObjectError("invalid blob hash format", nil)
	}

	repo := core.NewRepository(repoRoot)
	objectType, data, err := repo.ReadObject(hash)
	if err != nil {
		if core.IsErrNotFound(err) {
			return nil, core.NotFoundError(core.ErrCategoryObject, "blob "+hash[:8])
		}
		return nil, core.ObjectError("failed to read blob", err)
	}
	if objectType != "blob" {
		return nil, core.ObjectError("object is not a blob, but a "+objectType, nil)
	}
	return data, nil
}
