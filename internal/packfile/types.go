package packfile

import "fmt"

// Constants
const (
	hashLength     = 32 // SHA-256 hash length in bytes
	hexHashLength  = 64 // SHA-256 hash length in hex form
	TYPE_OFS_DELTA = 6  // Delta with offset to base
	TYPE_REF_DELTA = 7  // Delta with reference to base
)

// ObjectType represents the type of an object in the packfile
type ObjectType byte

const (
	OBJ_NONE      ObjectType = 0   // Not a valid object type
	OBJ_COMMIT    ObjectType = 1   // Commit object
	OBJ_TREE      ObjectType = 2   // Tree object
	OBJ_BLOB      ObjectType = 3   // Blob (file) object
	OBJ_TAG       ObjectType = 4   // Tag object
	OBJ_OFS_DELTA ObjectType = 6   // Delta with offset to base
	OBJ_REF_DELTA ObjectType = 7   // Delta with reference to base
	OBJ_DELTA     ObjectType = 100 // Internal delta representation
)

// Object represents a parsed object from a packfile
type Object struct {
	Hash          string           // SHA-256 hash in hex format
	HashBytes     [hashLength]byte // SHA-256 hash in bytes
	Type          ObjectType       // Object type
	Data          []byte           // Object data
	BaseHash      string           // Hash of base object (if delta)
	BaseHashBytes [hashLength]byte // Base hash in bytes (if delta)
	Offset        int64            // Offset in packfile
	Size          uint64           // Size of object data
	BaseIndex     int              // Index of base object in p.Objects array (if OFS_DELTA)
}

// DeltaObject represents a delta-compressed object
type DeltaObject struct {
	BaseHash      string           // Hash of base object
	BaseHashBytes [hashLength]byte // Base hash in bytes
	Hash          string           // Hash of resulting object
	HashBytes     [hashLength]byte // Resulting hash in bytes
	Type          ObjectType       // Type of final object
	Delta         []byte           // Delta instructions
	TargetSize    uint64           // Size of reconstructed object
}

// PackfileIndex represents an index for a packfile
type PackfileIndex struct {
	Fanout       [256]uint32        // Fanout table
	Offsets      []uint32           // Object offsets
	Hashes       [][hashLength]byte // Object hashes
	CRCs         []uint32           // CRC32 checksums
	PackChecksum [hashLength]byte   // Packfile checksum
}

// PackIndexEntry stores information about an object in the packfile
type PackIndexEntry struct {
	Offset uint64     // Offset in the packfile
	Type   ObjectType // Object type
	Size   uint64     // Size of the object data
	CRC32  uint32     // CRC32 checksum
}

// PackFileHeader represents the header of a packfile
type PackFileHeader struct {
	Signature  [4]byte // Should be "PACK"
	Version    uint32  // Pack format version (2)
	NumObjects uint32  // Number of objects
}

// typeToString converts an ObjectType to its string representation
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

// stringToType converts a string type name to ObjectType
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
