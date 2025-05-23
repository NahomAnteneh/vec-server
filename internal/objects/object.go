package objects

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/NahomAnteneh/vec-server/core"
)

// FindReachableObjectsRepo finds all objects reachable from a commit using Repository context.
func FindReachableObjects(repoRoot string, commitHash string) ([]string, error) {

	if repoRoot == "" {
		return nil, core.RepositoryError("empty repository path provided", nil)
	}
	repo := core.NewRepository(repoRoot)

	if repo == nil {
		return nil, core.ObjectError("nil repository provided", nil)
	}
	if commitHash == "" {
		return []string{}, nil
	}
	if len(commitHash) != 64 || !core.IsValidHex(commitHash) {
		return nil, core.ObjectError(fmt.Sprintf("invalid commit hash: %s", commitHash), nil)
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

		objPath := filepath.Join(repo.VecDir, "objects", hash[:2], hash[2:])
		if !core.FileExists(objPath) {
			return nil, core.NotFoundError(core.ErrCategoryObject, fmt.Sprintf("object %s", hash))
		}

		file, err := os.Open(objPath)
		if err != nil {
			return nil, core.ObjectError(fmt.Sprintf("failed to open object %s: %v", hash, err), err)
		}
		defer file.Close()

		zr, err := zlib.NewReader(file)
		if err != nil {
			return nil, core.ObjectError(fmt.Sprintf("failed to create zlib reader for %s: %v", hash, err), err)
		}
		defer zr.Close()

		content, err := io.ReadAll(zr)
		if err != nil {
			return nil, core.ObjectError(fmt.Sprintf("failed to read object %s: %v", hash, err), err)
		}

		nullIndex := bytes.IndexByte(content, 0)
		if nullIndex == -1 {
			return nil, core.ObjectError(fmt.Sprintf("invalid object format for %s", hash), nil)
		}

		header := string(content[:nullIndex])
		parts := strings.Split(header, " ")
		if len(parts) != 2 {
			return nil, core.ObjectError(fmt.Sprintf("invalid object header for %s", hash), nil)
		}

		objType := parts[0]
		switch objType {
		case "commit":
			commit, err := GetCommit(repoRoot, hash)
			if err != nil {
				return nil, core.ObjectError(fmt.Sprintf("failed to get commit %s: %v", hash, err), err)
			}
			objectsMap[commit.Tree] = true
			queue = append(queue, commit.Tree)
			queue = append(queue, commit.Parents...)
		case "tree":
			tree, err := GetTree(repoRoot, hash)
			if err != nil {
				return nil, core.ObjectError(fmt.Sprintf("failed to get tree %s: %v", hash, err), err)
			}
			for _, entry := range tree.Entries {
				objectsMap[entry.Hash] = true
				queue = append(queue, entry.Hash)
			}
		case "blob":
			// Blobs are terminal
		default:
			return nil, core.ObjectError(fmt.Sprintf("unknown object type %s for %s", objType, hash), nil)
		}
	}

	result := make([]string, 0, len(objectsMap))
	for obj := range objectsMap {
		result = append(result, obj)
	}
	return result, nil
}

// ObjectExistsRepo checks if an object exists in the repository.
func ObjectExists(repoRoot string, hash string) (bool, error) {
	if repoRoot == "" {
		return false, core.RepositoryError("empty repository path provided", nil)
	}
	repo := core.NewRepository(repoRoot)

	if repo == nil {
		return false, core.ObjectError("nil repository provided", nil)
	}
	if len(hash) != 64 || !core.IsValidHex(hash) {
		return false, nil
	}
	objPath := filepath.Join(repo.VecDir, "objects", hash[:2], hash[2:])
	return core.FileExists(objPath), nil
}

// ObjectExists checks if an object exists using repository path.
// func ObjectExists(repoRoot string, hash string) (bool, error) {
// 	if repoRoot == "" {
// 		return false, core.RepositoryError("empty repository path provided", nil)
// 	}
// 	repo := core.NewRepository(repoRoot)
// 	return ObjectExistsRepo(repo, hash)
// }
