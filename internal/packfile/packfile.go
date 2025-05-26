package packfile

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/NahomAnteneh/vec-server/core"
)

// FinalizePackfile prepares a packfile for transmission by adding checksums and other metadata
func FinalizePackfile(packfile []byte) []byte {
	// Calculate the SHA-256 checksum of the packfile content
	h := sha256.New()
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
	// Calculate SHA-256 checksum of the packfile
	h := sha256.New()
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
		fmt.Printf("  %s: %d objects\n", TypeToString(t), count)
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
func CreatePackfile(repo *core.Repository, objectHashes []string) ([]byte, error) {
	var objects []Object

	// Load each object and add to the list
	for _, hash := range objectHashes {
		objType, objData, err := core.ReadObject(repo.Root, hash)
		if err != nil {
			return nil, fmt.Errorf("failed to read object %s: %w", hash, err)
		}

		// Convert type string to ObjectType
		var objTypeEnum ObjectType
		switch objType {
		case "commit":
			objTypeEnum = OBJ_COMMIT
		case "tree":
			objTypeEnum = OBJ_TREE
		case "blob":
			objTypeEnum = OBJ_BLOB
		case "tag":
			objTypeEnum = OBJ_TAG
		default:
			return nil, fmt.Errorf("unknown object type %s for %s", objType, hash)
		}

		objects = append(objects, Object{
			Hash: hash,
			Type: objTypeEnum,
			Data: objData,
		})
	}

	// Create the packfile from the objects
	return CreatePackfileFromObjects(objects)
}

// CreatePackfileFromHashesRepo creates a packfile on disk from a list of object hashes
func CreatePackfileFromHashesRepo(repo *core.Repository, objectHashes []string, outputPath string, withDeltaCompression bool) error {
	// Load objects from the repository
	objects := make([]Object, 0, len(objectHashes))
	for _, hash := range objectHashes {
		// Get object file path
		prefix := hash[:2]
		suffix := hash[2:]
		objectPath := filepath.Join(repo.VecDir, "objects", prefix, suffix)

		// Read the compressed object data
		compressedData, err := os.ReadFile(objectPath)
		if err != nil {
			// Skip objects that can't be read
			fmt.Printf("Warning: Couldn't read object %s: %v\n", hash, err)
			continue
		}

		// Create a reader for decompression
		zr, err := zlib.NewReader(bytes.NewReader(compressedData))
		if err != nil {
			fmt.Printf("Warning: Couldn't decompress object %s: %v\n", hash, err)
			continue
		}

		// Read the decompressed content
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, zr); err != nil {
			zr.Close()
			fmt.Printf("Warning: Error reading decompressed data for %s: %v\n", hash, err)
			continue
		}
		zr.Close()

		// Parse the header to get the object type
		content := buf.Bytes()
		nullIndex := bytes.IndexByte(content, 0)
		if nullIndex == -1 {
			fmt.Printf("Warning: Invalid object format for %s\n", hash)
			continue
		}

		parts := bytes.SplitN(content[:nullIndex], []byte(" "), 2)
		if len(parts) != 2 {
			fmt.Printf("Warning: Invalid object header format for %s\n", hash)
			continue
		}

		// Determine object type
		var objType ObjectType // Default to zero value (OBJ_NONE)
		switch string(parts[0]) {
		case "commit":
			objType = OBJ_COMMIT
		case "tree":
			objType = OBJ_TREE
		case "blob":
			objType = OBJ_BLOB
		// case "tag": // If tags are supported by the object storage
		// 	objType = OBJ_TAG
		default:
			fmt.Printf("Warning: Unknown object type '%s' for %s. Skipping object.\n", string(parts[0]), hash)
			continue // Skip this object as its type is not recognized
		}

		// Add the object to our collection
		var hashBytes [hashLength]byte
		decoded, err := hex.DecodeString(hash)
		if err == nil {
			copy(hashBytes[:], decoded)
		}

		objects = append(objects, Object{
			Hash:      hash,
			HashBytes: hashBytes,
			Type:      objType,
			Data:      content[nullIndex+1:],
			Size:      uint64(len(content[nullIndex+1:])),
		})
	}

	// Apply delta compression if requested
	if withDeltaCompression {
		optimizedObjects, err := OptimizeObjects(objects)
		if err != nil {
			return fmt.Errorf("failed to optimize objects: %w", err)
		}
		return CreateModernPackfile(optimizedObjects, outputPath)
	}

	// Create a simple packfile without delta compression
	return CreateModernPackfile(objects, outputPath)
}
