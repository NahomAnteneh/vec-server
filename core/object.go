package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashFile calculates the SHA-256 hash of a file, including the Vec object header.
func HashFile(filePath string) (string, error) {
	content, err := ReadFileContent(filePath)
	if err != nil {
		return "", err
	}
	return HashBytes("blob", content), nil
}

// HashBytes calculates the SHA-256 hash of the given data, including the Vec object header.
func HashBytes(objectType string, data []byte) string {
	header := fmt.Sprintf("%s %d\x00", objectType, len(data))
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// IsValidHex checks if a string is a valid hexadecimal value.
func IsValidHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ObjectExists checks if an object exists in the object store.
func ObjectExists(repo *Repository, hash string) (bool, error) {
	if repo == nil {
		return false, RepositoryError("nil repository", nil)
	}
	if len(hash) != 64 || !IsValidHex(hash) {
		return false, nil
	}
	objPath, err := GetObjectPath(repo, hash)
	if err != nil {
		return false, err
	}
	return FileExists(objPath), nil
}

// FindReachableObjects finds all objects reachable from a commit using repository path.
func FindReachableObjects(repo *Repository, commitHash string) ([]string, error) {
	if repo == nil {
		return nil, RepositoryError("nil repository", nil)
	}
	if commitHash == "" {
		return []string{}, nil
	}
	if len(commitHash) != 64 || !IsValidHex(commitHash) {
		return nil, ObjectError(fmt.Sprintf("invalid commit hash: %s", commitHash), nil)
	}

	objectsMap := make(map[string]bool)
	visited := make(map[string]bool)
	queue := []string{commitHash}

	for len(queue) > 0 {
		hash := queue[0]
		queue = queue[1:]

		if visited[hash] {
			continue
		}
		visited[hash] = true
		objectsMap[hash] = true

		objPath, err := GetObjectPath(repo, hash)
		if err != nil {
			return nil, err
		}
		if !FileExists(objPath) {
			return nil, NotFoundError(ErrCategoryObject, fmt.Sprintf("object %s", hash))
		}

		objType, _, err := ReadObject(repo, hash)
		if err != nil {
			return nil, ObjectError(fmt.Sprintf("failed to read object %s", hash), err)
		}

		switch objType {
		case "commit":
			commit, err := GetCommit(repo.Root, hash)
			if err != nil {
				return nil, ObjectError(fmt.Sprintf("failed to get commit %s", hash), err)
			}
			objectsMap[commit.Tree] = true
			queue = append(queue, commit.Tree)
			queue = append(queue, commit.Parents...)
		case "tree":
			tree, err := GetTree(repo.Root, hash)
			if err != nil {
				return nil, ObjectError(fmt.Sprintf("failed to get tree %s", hash), err)
			}
			for _, entry := range tree.Entries {
				objectsMap[entry.Hash] = true
				queue = append(queue, entry.Hash)
			}
		case "blob":
			// Blobs are terminal
		default:
			return nil, ObjectError(fmt.Sprintf("unknown object type %s for %s", objType, hash), nil)
		}
	}

	result := make([]string, 0, len(objectsMap))
	for obj := range objectsMap {
		result = append(result, obj)
	}
	return result, nil
}
