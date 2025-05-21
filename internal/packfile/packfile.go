// Package packfile provides functionality for working with packfiles,
// which are used to efficiently store and transfer multiple objects.
package packfile

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/NahomAnteneh/vec-server/internal/objects"
)

// FinalizePackfile prepares a packfile for transmission by adding checksums and other metadata
func FinalizePackfile(packfile []byte) []byte {
	// Calculate the SHA-1 checksum of the packfile content
	h := sha1.New()
	h.Write(packfile)
	checksum := h.Sum(nil)

	// Append the checksum to the packfile
	finalizedPackfile := make([]byte, len(packfile)+len(checksum))
	copy(finalizedPackfile, packfile)
	copy(finalizedPackfile[len(packfile):], checksum)

	return finalizedPackfile
}

// CalculatePackfileChecksum calculates a checksum for the packfile
func CalculatePackfileChecksum(packfile []byte) []byte {
	// Calculate SHA-1 checksum of the packfile
	h := sha1.New()
	h.Write(packfile)
	return h.Sum(nil)
}

// FormatHash formats a binary hash as a hex string
func FormatHash(hash []byte) string {
	return hex.EncodeToString(hash)
}

// ParseHash parses a hex string into a binary hash
func ParseHash(hashStr string) ([]byte, error) {
	return hex.DecodeString(hashStr)
}

// PrintPackfileStats prints statistics about a packfile
func PrintPackfileStats(objects []Object) {
	fmt.Printf("Packfile contains %d objects\n", len(objects))

	// Count objects by type
	typeCounts := make(map[ObjectType]int)
	for _, obj := range objects {
		typeCounts[obj.Type]++
	}

	// Print counts by type
	for t, count := range typeCounts {
		fmt.Printf("  %s: %d objects\n", typeToString(t), count)
	}

	// Calculate and print total data size
	var totalSize int
	for _, obj := range objects {
		totalSize += len(obj.Data)
	}
	fmt.Printf("  Total data size: %d bytes\n", totalSize)
}

// CreatePackfile creates a packfile from a list of object hashes in a repository
// and returns the binary packfile data for remote operations
func CreatePackfile(repoRoot string, objectHashes []string) ([]byte, error) {
	// Create a temporary file to store the packfile
	tempDir := os.TempDir()
	tempFile, err := os.CreateTemp(tempDir, "vec-packfile-*.pack")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary packfile: %w", err)
	}
	tempFilePath := tempFile.Name()
	tempFile.Close() // Close immediately as we'll reopen it later

	// Clean up the temporary file when done
	defer os.Remove(tempFilePath)

	// Create the packfile using the repository objects
	if err := CreatePackfileFromHashes(repoRoot, objectHashes, tempFilePath, true); err != nil {
		return nil, fmt.Errorf("failed to create packfile: %w", err)
	}

	// Read the packfile contents
	packfileData, err := os.ReadFile(tempFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read packfile: %w", err)
	}

	return packfileData, nil
}

// CreatePackfileFromHashes creates a packfile from a list of object hashes in a repository.
func CreatePackfileFromHashes(repoPath string, objectHashes []string, outputPath string, withDeltaCompression bool) error {
	// Load objects from the repository
	loadedObjects := make([]Object, 0, len(objectHashes))
	for _, hash := range objectHashes {
		// Get object file path using the objects package
		objectPath := objects.GetObjectPath(repoPath, hash)

		// Read the object data
		objType, objData, err := objects.ReadObject(repoPath, hash)
		if err != nil {
			// Skip objects that can't be read
			fmt.Printf("Warning: Couldn't read object %s: %v\n", hash, err)
			continue
		}

		// Determine object type
		var objTypeByte ObjectType // Default to zero value (OBJ_NONE)
		switch objType {
		case "commit":
			objTypeByte = OBJ_COMMIT
		case "tree":
			objTypeByte = OBJ_TREE
		case "blob":
			objTypeByte = OBJ_BLOB
		case "tag":
			objTypeByte = OBJ_TAG
		default:
			fmt.Printf("Warning: Unknown object type '%s' for %s. Skipping object.\n", objType, hash)
			continue // Skip this object as its type is not recognized
		}

		// Add the object to our collection
		loadedObjects = append(loadedObjects, Object{
			Hash: hash,
			Type: objTypeByte,
			Data: objData,
		})
	}

	// Apply delta compression if requested
	if withDeltaCompression && len(loadedObjects) > 1 {
		var err error
		loadedObjects, err = OptimizeObjects(loadedObjects)
		if err != nil {
			return fmt.Errorf("failed to optimize objects: %w", err)
		}
	}

	// Create the packfile
	return CreateModernPackfile(loadedObjects, outputPath)
}
