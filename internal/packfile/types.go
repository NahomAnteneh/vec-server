package packfile

import "fmt"

// Constants
const (
	hashLength = 40 // SHA-1 hash length in hex form (20 bytes represented as 40 hex characters)

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
	Hash string     // SHA-1 hash in hex format
	Type ObjectType // Object type
	Data []byte     // Object data

	// For delta objects
	BaseHash string // Hash of base object (if this is a delta)
}

// DeltaObject represents a delta object with a base object hash and delta instructions
type DeltaObject struct {
	BaseHash string     // Hash of the base object
	Hash     string     // Hash of the resulting object after applying delta
	Type     ObjectType // Type of the final object (inherited from base)
	Delta    []byte     // Delta instructions
}

// PackfileIndex represents an index for a packfile
type PackfileIndex struct {
	Version  uint32                    // Index format version
	Entries  map[string]PackIndexEntry // Map from hash to entry
	Checksum []byte                    // SHA-1 checksum of the packfile
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

// typeToString converts an ObjectType to its string representation
func typeToString(objType ObjectType) string {
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

// stringToType converts a string type name to ObjectType
func stringToType(typeName string) ObjectType {
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
