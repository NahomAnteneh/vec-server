package packfile

import (
	"encoding/hex"
	"fmt"
)

// Constants
const (
	hashLength    = 32 // SHA-256 hash length in bytes
	hexHashLength = 64 // SHA-256 hash length in hex form (32 bytes represented as 64 hex characters)

	// Object type bits in packed format
	TYPE_OFS_DELTA = 6 // Delta with offset to base
	TYPE_REF_DELTA = 7 // Delta with reference to base
)

// ObjectType represents the type of an object in the packfile
type ObjectType byte

const (
	// Standard object types in Git
	OBJ_NONE   ObjectType = 0 // Not a valid object type
	OBJ_COMMIT ObjectType = 1 // Commit object
	OBJ_TREE   ObjectType = 2 // Tree object
	OBJ_BLOB   ObjectType = 3 // Blob (file) object
	OBJ_TAG    ObjectType = 4 // Tag object

	// Reserved for future use
	OBJ_OFS_DELTA ObjectType = 6 // Delta with offset to base
	OBJ_REF_DELTA ObjectType = 7 // Delta with reference to base

	// Our custom object type for internal use only
	OBJ_DELTA ObjectType = 100 // Delta object (for internal representation)
)

// Object represents a parsed object from a packfile.
type Object struct {
	Hash          string           // SHA-256 hash in hex format
	HashBytes     [hashLength]byte // SHA-256 hash in bytes
	Type          ObjectType       // Object type
	Data          []byte           // Object data
	BaseHash      string           // Hash of base object (if this is a delta)
	BaseHashBytes [hashLength]byte // Base hash in bytes (if delta)
	Offset        int64            // Offset in packfile
	Size          uint64           // Size of object data
	BaseIndex     int              // Index of base object in objects array (if OFS_DELTA)
}

// DeltaObject represents a delta object with a base object hash and delta instructions
type DeltaObject struct {
	BaseHash      string           // Hash of the base object
	BaseHashBytes [hashLength]byte // Base hash in bytes
	Hash          string           // Hash of the resulting object after applying delta
	HashBytes     [hashLength]byte // Resulting hash in bytes
	Type          ObjectType       // Type of the final object (inherited from base)
	Delta         []byte           // Delta instructions
	TargetSize    uint64           // Size of reconstructed object
}

// PackfileIndex represents an index for a packfile
type PackfileIndex struct {
	Version      uint32                    // Index format version
	Entries      map[string]PackIndexEntry // Map from hash to entry
	Checksum     []byte                    // SHA-256 checksum of the packfile
	Fanout       [256]uint32               // Fanout table
	Offsets      []uint32                  // Object offsets
	Hashes       [][hashLength]byte        // Object hashes
	CRCs         []uint32                  // CRC32 checksums
	PackChecksum [hashLength]byte          // Packfile checksum
}

// PackIndexEntry stores information about an object in the packfile
type PackIndexEntry struct {
	Offset uint64     // Offset in the packfile
	Type   ObjectType // Object type
	Size   uint64     // Size of the object data
	CRC32  uint32     // CRC32 checksum (optional)
}

// PackFileHeader represents the header of a packfile
type PackFileHeader struct {
	Signature  [4]byte // Should be "PACK"
	Version    uint32  // Pack format version (currently 2)
	NumObjects uint32  // Number of objects in the pack
}

// TypeToString converts an ObjectType to its string representation
func TypeToString(objType ObjectType) string {
	switch objType {
	case OBJ_COMMIT:
		return "commit"
	case OBJ_TREE:
		return "tree"
	case OBJ_BLOB:
		return "blob"
	case OBJ_TAG:
		return "tag"
	case OBJ_DELTA, OBJ_REF_DELTA, OBJ_OFS_DELTA:
		return "delta"
	case OBJ_NONE:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", objType)
	}
}

// StringToType converts a string type name to ObjectType
func StringToType(typeName string) ObjectType {
	switch typeName {
	case "commit":
		return OBJ_COMMIT
	case "tree":
		return OBJ_TREE
	case "blob":
		return OBJ_BLOB
	case "tag":
		return OBJ_TAG
	case "delta":
		return OBJ_DELTA
	default:
		return OBJ_NONE
	}
}

// For backward compatibility
func typeToString(objType ObjectType) string {
	return TypeToString(objType)
}

// For backward compatibility
func stringToType(typeName string) ObjectType {
	return StringToType(typeName)
}

// Helper function to convert hex string to byte array
func hexToBytes(hexStr string) ([hashLength]byte, error) {
	var result [hashLength]byte
	if len(hexStr) != hexHashLength {
		return result, fmt.Errorf("invalid hash length: expected %d, got %d", hexHashLength, len(hexStr))
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, err
	}

	copy(result[:], bytes)
	return result, nil
}
