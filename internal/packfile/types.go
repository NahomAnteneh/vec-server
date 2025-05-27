package packfile

import "fmt"

// Constants
const (
	TYPE_OFS_DELTA = 6 // Delta with offset to base
	TYPE_REF_DELTA = 7 // Delta with reference to base
)

// ObjectType represents the type of an object in the packfile
type ObjectType byte

const (
	OBJ_NONE      ObjectType = 0 // Not a valid object type
	OBJ_COMMIT    ObjectType = 1 // Commit object
	OBJ_TREE      ObjectType = 2 // Tree object
	OBJ_BLOB      ObjectType = 3 // Blob (file) object
	OBJ_TAG       ObjectType = 4 // Tag object
	OBJ_OFS_DELTA ObjectType = 6 // Delta with offset to base
	OBJ_REF_DELTA ObjectType = 7 // Delta with reference to base
)

// IsValid checks if the object type is valid
func (t ObjectType) IsValid() bool {
	return t == OBJ_COMMIT || t == OBJ_TREE || t == OBJ_BLOB || t == OBJ_TAG ||
		t == OBJ_OFS_DELTA || t == OBJ_REF_DELTA
}

// IsDelta checks if the object type is a delta type
func (t ObjectType) IsDelta() bool {
	return t == OBJ_OFS_DELTA || t == OBJ_REF_DELTA
}

// Object represents a parsed object from a packfile
type Object struct {
	Hash          string     // Hash in hex format
	HashBytes     []byte     // Hash in bytes
	Type          ObjectType // Object type
	Data          []byte     // Object data
	BaseHash      string     // Hash of base object (if delta)
	BaseHashBytes []byte     // Base hash in bytes (if delta)
	Offset        int64      // Offset in packfile
	Size          uint64     // Size of object data
	BaseIndex     int        // Index of base object in p.Objects array (if OFS_DELTA)
}

// Validate checks if the object is valid
func (o *Object) Validate(hashLength int) error {
	if !o.Type.IsValid() {
		return fmt.Errorf("invalid object type: %d", o.Type)
	}

	if len(o.Hash) != hashLength*2 {
		return fmt.Errorf("invalid hash length: %d, expected %d", len(o.Hash), hashLength*2)
	}

	if len(o.HashBytes) != hashLength {
		return fmt.Errorf("invalid hash bytes length: %d, expected %d", len(o.HashBytes), hashLength)
	}

	if o.Type.IsDelta() {
		// Validate base hash for reference deltas
		if o.Type == OBJ_REF_DELTA {
			if o.BaseHash == "" {
				return fmt.Errorf("missing base hash for OBJ_REF_DELTA")
			}
			if len(o.BaseHash) != hashLength*2 {
				return fmt.Errorf("invalid base hash length: %d, expected %d",
					len(o.BaseHash), hashLength*2)
			}
			if len(o.BaseHashBytes) != hashLength {
				return fmt.Errorf("invalid base hash bytes length: %d, expected %d",
					len(o.BaseHashBytes), hashLength)
			}
		} else if o.Type == OBJ_OFS_DELTA {
			// For offset deltas, validate BaseIndex
			if o.BaseIndex < 0 {
				return fmt.Errorf("invalid negative BaseIndex: %d", o.BaseIndex)
			}
		}
	}

	if o.Offset < 0 {
		return fmt.Errorf("invalid negative offset: %d", o.Offset)
	}

	return nil
}

// ValidateBaseIndex checks if BaseIndex is valid for the given objects slice
func (o *Object) ValidateBaseIndex(objects []Object) error {
	if o.Type != OBJ_OFS_DELTA {
		return nil
	}
	if o.BaseIndex < 0 || o.BaseIndex >= len(objects) {
		return fmt.Errorf("invalid BaseIndex %d for object at offset %d", o.BaseIndex, o.Offset)
	}
	return nil
}

// DeltaObject represents a delta-compressed object
type DeltaObject struct {
	BaseHash      string     // Hash of base object
	BaseHashBytes []byte     // Base hash in bytes
	Hash          string     // Hash of resulting object
	HashBytes     []byte     // Resulting hash in bytes
	Type          ObjectType // Type of final object
	Delta         []byte     // Delta instructions
	TargetSize    uint64     // Size of reconstructed object
}

// Validate checks if the delta object is valid
func (d *DeltaObject) Validate(hashLength int) error {
	if !d.Type.IsValid() {
		return fmt.Errorf("invalid object type: %d", d.Type)
	}

	if len(d.Hash) != hashLength*2 {
		return fmt.Errorf("invalid hash length: %d, expected %d", len(d.Hash), hashLength*2)
	}

	if len(d.HashBytes) != hashLength {
		return fmt.Errorf("invalid hash bytes length: %d, expected %d", len(d.HashBytes), hashLength)
	}

	if d.BaseHash == "" {
		return fmt.Errorf("missing base hash for delta object")
	}

	if len(d.BaseHash) != hashLength*2 {
		return fmt.Errorf("invalid base hash length: %d, expected %d", len(d.BaseHash), hashLength*2)
	}

	if len(d.BaseHashBytes) != hashLength {
		return fmt.Errorf("invalid base hash bytes length: %d, expected %d", len(d.BaseHashBytes), hashLength)
	}

	if len(d.Delta) == 0 {
		return fmt.Errorf("empty delta instructions")
	}

	return nil
}

// PackfileIndex represents an index for a packfile
type PackfileIndex struct {
	Fanout       [256]uint32 // Fanout table
	Offsets      []uint32    // Object offsets
	Hashes       [][]byte    // Object hashes
	CRCs         []uint32    // CRC32 checksums
	PackChecksum []byte      // Packfile checksum
}

// Validate checks if the index is valid
func (idx *PackfileIndex) Validate(hashLength int) error {
	if len(idx.Offsets) != len(idx.Hashes) || len(idx.Offsets) != len(idx.CRCs) {
		return fmt.Errorf("mismatched array lengths: offsets=%d, hashes=%d, crcs=%d",
			len(idx.Offsets), len(idx.Hashes), len(idx.CRCs))
	}

	if len(idx.PackChecksum) != hashLength {
		return fmt.Errorf("invalid pack checksum length: %d, expected %d",
			len(idx.PackChecksum), hashLength)
	}

	for i, hash := range idx.Hashes {
		if len(hash) != hashLength {
			return fmt.Errorf("invalid hash length at index %d: %d, expected %d",
				i, len(hash), hashLength)
		}
	}

	// Verify fanout table consistency
	if len(idx.Offsets) > 0 && idx.Fanout[255] != uint32(len(idx.Offsets)) {
		return fmt.Errorf("fanout table inconsistency: fanout[255]=%d, object count=%d",
			idx.Fanout[255], len(idx.Offsets))
	}

	return nil
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

// Validate checks if the header is valid
func (h *PackFileHeader) Validate() error {
	if string(h.Signature[:]) != "PACK" {
		return fmt.Errorf("invalid signature: %s", string(h.Signature[:]))
	}

	if h.Version != 2 {
		return fmt.Errorf("unsupported version: %d, expected 2", h.Version)
	}

	return nil
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
	case OBJ_OFS_DELTA, OBJ_REF_DELTA:
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
		return OBJ_OFS_DELTA // Default to OFS_DELTA for delta types
	default:
		return OBJ_NONE
	}
}
