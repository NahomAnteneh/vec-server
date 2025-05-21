package packfile

import (
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/NahomAnteneh/vec-server/internal/objects"
)

// Parser parses packfiles and extracts objects
type Parser struct {
	reader io.Reader
}

// NewParser creates a new packfile parser
func NewParser(reader io.Reader) *Parser {
	return &Parser{reader: reader}
}

// Parse parses the packfile and returns the objects
func (p *Parser) Parse() ([]*objects.Object, error) {
	// Read and verify header
	header := make([]byte, 12)
	if _, err := io.ReadFull(p.reader, header); err != nil {
		return nil, fmt.Errorf("failed to read packfile header: %w", err)
	}

	// Check signature
	if string(header[0:4]) != "PACK" {
		return nil, errors.New("invalid packfile: bad signature")
	}

	// Check version
	version := binary.BigEndian.Uint32(header[4:8])
	if version != 2 {
		return nil, fmt.Errorf("unsupported packfile version: %d", version)
	}

	// Get number of objects
	numObjects := binary.BigEndian.Uint32(header[8:12])

	// Parse objects
	var result []*objects.Object
	for i := uint32(0); i < numObjects; i++ {
		obj, err := p.parseObject()
		if err != nil {
			return nil, fmt.Errorf("failed to parse object %d: %w", i, err)
		}
		result = append(result, obj)
	}

	return result, nil
}

// parseObject parses a single object from the packfile
func (p *Parser) parseObject() (*objects.Object, error) {
	// Read object header (type and size)
	objType, size, err := p.readObjectHeader()
	if err != nil {
		return nil, err
	}

	// Map packfile object type to Vec object type
	var vecObjType objects.ObjectType
	switch objType {
	case 1:
		vecObjType = objects.ObjectTypeCommit
	case 2:
		vecObjType = objects.ObjectTypeTree
	case 3:
		vecObjType = objects.ObjectTypeBlob
	case 4:
		vecObjType = objects.ObjectTypeTag
	default:
		return nil, fmt.Errorf("unsupported object type: %d", objType)
	}

	// Read compressed data
	zlibReader, err := zlib.NewReader(p.reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zlibReader.Close()

	// Read object data
	data := make([]byte, size)
	if _, err := io.ReadFull(zlibReader, data); err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	// Create object
	obj := &objects.Object{
		Type:    vecObjType,
		Content: data,
	}

	// Calculate hash
	obj.Hash, err = objects.HashObject(data, vecObjType)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate object hash: %w", err)
	}

	return obj, nil
}

// readObjectHeader reads the object type and size from the packfile
func (p *Parser) readObjectHeader() (byte, uint64, error) {
	// Read first byte
	var firstByte [1]byte
	if _, err := io.ReadFull(p.reader, firstByte[:]); err != nil {
		return 0, 0, fmt.Errorf("failed to read object header: %w", err)
	}

	// Extract type and initial size
	objType := (firstByte[0] >> 4) & 0x7
	size := uint64(firstByte[0] & 0x0F)
	shift := uint(4)

	// Read variable-length size
	for firstByte[0]&0x80 != 0 {
		var b [1]byte
		if _, err := io.ReadFull(p.reader, b[:]); err != nil {
			return 0, 0, fmt.Errorf("failed to read object size: %w", err)
		}

		size |= uint64(b[0]&0x7F) << shift
		shift += 7

		// Check for continuation bit
		if b[0]&0x80 == 0 {
			break
		}
	}

	return objType, size, nil
}

// ParsePackfile parses the binary packfile and returns a slice of objects.
// Maintains backward compatibility with the original function.
func ParsePackfile(packfile []byte) ([]Object, error) {
	if len(packfile) < 4 {
		return nil, errors.New("packfile too short: missing object count")
	}

	numObjects := binary.BigEndian.Uint32(packfile[:4])
	objects := make([]Object, 0, numObjects)
	offset := 4

	for i := 0; i < int(numObjects); i++ {
		if offset+hashLength+4 > len(packfile) {
			return nil, errors.New("packfile format error: incomplete object header")
		}

		hashBytes := packfile[offset : offset+hashLength]
		hash := string(hashBytes) // Assumes hash is stored as a hex string.
		offset += hashLength

		dataLen := int(binary.BigEndian.Uint32(packfile[offset : offset+4]))
		offset += 4

		// Read the object type (1 byte)
		objType := ObjectType(0)
		if offset < len(packfile) {
			objType = ObjectType(packfile[offset])
			offset++
		} else {
			return nil, errors.New("packfile format error: missing object type")
		}

		// Object data follows the type byte
		if offset+dataLen-1 > len(packfile) {
			return nil, fmt.Errorf("packfile format error: incomplete object data (expected %d bytes, have %d)",
				dataLen-1, len(packfile)-offset)
		}

		// The data length includes the type byte, so we need dataLen-1 bytes for actual data
		data := packfile[offset : offset+dataLen-1]
		offset += dataLen - 1

		objects = append(objects, Object{
			Hash: hash,
			Type: objType,
			Data: data,
		})
	}

	return objects, nil
}

// ParseModernPackfile parses a modern packfile (with compression and deltas) and returns objects
func ParseModernPackfile(packfilePath string, useIndex bool) ([]Object, error) {
	// Open the packfile
	file, err := os.Open(packfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open packfile: %w", err)
	}
	defer file.Close()

	// Read and verify header
	header := PackFileHeader{}
	if err := binary.Read(file, binary.BigEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read packfile header: %w", err)
	}

	if string(header.Signature[:]) != "PACK" {
		return nil, errors.New("invalid packfile: bad signature")
	}

	if header.Version != 2 {
		return nil, fmt.Errorf("unsupported packfile version: %d", header.Version)
	}

	// Store object locations and information
	type objectInfo struct {
		offset   int64  // File offset of object
		isDelta  bool   // Whether this is a delta object
		baseHash string // Base object hash (for REF_DELTA)
		basePos  int64  // Base object position (for OFS_DELTA)
	}

	// Store information about each object
	objectInfos := make(map[uint64]objectInfo, header.NumObjects)
	objectsByOffset := make(map[int64]*Object) // For resolving offset deltas

	// First pass: scan the packfile and collect object metadata
	_, err = file.Seek(12, 0) // Skip header (12 bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to seek in packfile: %w", err)
	}

	// Track positions of all objects for delta resolution
	for i := uint32(0); i < header.NumObjects; i++ {
		// Record current position
		pos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get position for object %d: %w", i, err)
		}

		// Read object type and size from header
		headerByte, err := readByte(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read header for object %d: %w", i, err)
		}

		// Extract type and size
		objType := ObjectType((headerByte >> 4) & 0x7)
		size := uint64(headerByte & 0x0F)
		shift := uint(4)

		// Read variable-length size
		for headerByte&0x80 != 0 {
			headerByte, err = readByte(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read size for object %d: %w", i, err)
			}
			size |= uint64(headerByte&0x7F) << shift
			shift += 7
		}

		// Determine if this is a delta and record base information
		info := objectInfo{offset: pos}

		if objType == OBJ_REF_DELTA {
			info.isDelta = true

			// Read base hash for reference delta
			baseHashBytes := make([]byte, 20)
			if _, err := io.ReadFull(file, baseHashBytes); err != nil {
				return nil, fmt.Errorf("failed to read base hash for object %d: %w", i, err)
			}
			info.baseHash = fmt.Sprintf("%x", baseHashBytes)
		} else if objType == OBJ_OFS_DELTA {
			info.isDelta = true

			// Read offset delta encoding
			var baseOffset uint64
			var b byte = 0x80
			var j uint = 0

			for (b & 0x80) != 0 {
				b, err = readByte(file)
				if err != nil {
					return nil, fmt.Errorf("failed to read delta offset for object %d: %w", i, err)
				}

				baseOffset |= uint64(b&0x7F) << (j * 7)
				j++

				// Break if no more bytes (MSB not set)
				if (b & 0x80) == 0 {
					break
				}
			}

			// Calculate base position
			info.basePos = pos - int64(baseOffset)
		}

		// Record this object
		objectInfos[uint64(i)] = info

		// Skip compressed data - we'll read it in the second pass
		// Create zlib reader
		zlibReader, err := zlib.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader for object %d: %w", i, err)
		}

		// Skip the compressed data
		_, err = io.Copy(io.Discard, zlibReader)
		if err != nil {
			zlibReader.Close()
			return nil, fmt.Errorf("failed to skip data for object %d: %w", i, err)
		}
		zlibReader.Close()
	}

	// Second pass: read non-delta objects
	var objects []Object
	var deltaObjects []struct {
		objIndex uint64
		info     objectInfo
	}

	// Process non-delta objects first
	for objIndex, info := range objectInfos {
		if !info.isDelta {
			// Seek to the object
			_, err = file.Seek(info.offset, 0)
			if err != nil {
				return nil, fmt.Errorf("failed to seek to object at offset %d: %w", info.offset, err)
			}

			// Read the object
			obj, err := readPackObject(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read object at offset %d: %w", info.offset, err)
			}

			// Calculate hash for non-delta objects
			obj.Hash = calculateObjectHash(obj.Type, obj.Data)

			// Store the object
			objects = append(objects, *obj)
			objectsByOffset[info.offset] = obj
		} else {
			// Collect delta objects for third pass
			deltaObjects = append(deltaObjects, struct {
				objIndex uint64
				info     objectInfo
			}{objIndex, info})
		}
	}

	// Sort delta objects to ensure base objects are processed before dependent deltas
	sort.Slice(deltaObjects, func(i, j int) bool {
		infoI, infoJ := deltaObjects[i].info, deltaObjects[j].info

		// Process REF_DELTA before OFS_DELTA
		if infoI.baseHash != "" && infoJ.baseHash == "" {
			return true
		}
		if infoI.baseHash == "" && infoJ.baseHash != "" {
			return false
		}

		// For OFS_DELTA, process in order of base offset (lowest first)
		if infoI.baseHash == "" {
			return infoI.basePos < infoJ.basePos
		}

		// Default to lower index first
		return deltaObjects[i].objIndex < deltaObjects[j].objIndex
	})

	// Third pass: resolve and apply deltas
	for _, d := range deltaObjects {
		info := d.info // This info is from the first pass and reliably tells us delta type and base ref

		// Seek to the object
		_, err = file.Seek(info.offset, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to seek to delta at offset %d: %w", info.offset, err)
		}

		// Read the delta object (which includes its specific delta type and delta data)
		deltaRawObj, err := readPackObject(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read delta object at offset %d: %w", info.offset, err)
		}

		// Verify that what we read is indeed a delta, consistent with the first pass info
		if !(deltaRawObj.Type == OBJ_REF_DELTA || deltaRawObj.Type == OBJ_OFS_DELTA) {
			return nil, fmt.Errorf("object at offset %d was expected to be a delta, but read as type %s",
				info.offset, typeToString(deltaRawObj.Type))
		}

		// Find the base object
		var baseObj *Object

		if info.isDelta && info.baseHash != "" { // This was identified as REF_DELTA in the first pass
			if deltaRawObj.Type != OBJ_REF_DELTA {
				return nil, fmt.Errorf("mismatch: first pass said REF_DELTA, readPackObject returned %s for delta at %d", typeToString(deltaRawObj.Type), info.offset)
			}
			// Find the base by hash
			foundBase := false
			for i := range objects {
				if objects[i].Hash == info.baseHash { // info.baseHash is from the first pass scan
					baseObj = &objects[i]
					foundBase = true
					break
				}
			}
			if !foundBase {
				return nil, fmt.Errorf("base object with hash %s not found for REF_DELTA at offset %d", info.baseHash, info.offset)
			}
		} else if info.isDelta { // This was identified as OFS_DELTA in the first pass (baseHash would be empty in info)
			if deltaRawObj.Type != OBJ_OFS_DELTA {
				return nil, fmt.Errorf("mismatch: first pass said OFS_DELTA, readPackObject returned %s for delta at %d", typeToString(deltaRawObj.Type), info.offset)
			}
			// Find the base by offset
			baseObj = objectsByOffset[info.basePos] // info.basePos is from the first pass scan
		} else {
			// Should not happen as we are iterating d.info which are all deltas
			return nil, fmt.Errorf("internal error: processing non-delta in delta loop at offset %d", info.offset)
		}

		if baseObj == nil {
			var baseRefStr string
			if info.baseHash != "" {
				baseRefStr = "hash " + info.baseHash
			} else {
				baseRefStr = fmt.Sprintf("offset %d", info.basePos)
			}
			return nil, fmt.Errorf("base object not found for delta at offset %d (type %s, baseRef: %s)",
				info.offset, typeToString(deltaRawObj.Type), baseRefStr)
		}

		// Apply the delta
		resultData, err := applyDelta(baseObj.Data, deltaRawObj.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to apply delta at offset %d (base type %s, delta type %s): %w",
				info.offset, typeToString(baseObj.Type), typeToString(deltaRawObj.Type), err)
		}

		// Create the resulting object
		resultObj := Object{
			Type: baseObj.Type, // Inherit type from base
			Data: resultData,
		}

		// Calculate the hash
		resultObj.Hash = calculateObjectHash(resultObj.Type, resultObj.Data)

		// Store the resolved object
		objects = append(objects, resultObj)
		objectsByOffset[info.offset] = &objects[len(objects)-1]
	}

	return objects, nil
}

// readPackObject reads a single object from a packfile
// It returns the raw object, which could be a delta object (Type=OBJ_REF_DELTA or OBJ_OFS_DELTA)
// or a non-delta object.
func readPackObject(file *os.File) (*Object, error) {
	// Start position for this object
	startPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to get file position: %w", err)
	}

	// Read the first byte of the header
	headerByte, err := readByte(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read object header: %w", err)
	}

	// Extract object type (bits 4-6) and the first 4 bits of size from the header
	objectType := ObjectType((headerByte >> 4) & 0x7)
	size := uint64(headerByte & 0x0F)
	shift := uint(4)

	// Parse variable-length size encoding
	for headerByte&0x80 != 0 {
		headerByte, err = readByte(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read size continuation: %w", err)
		}
		size |= uint64(headerByte&0x7F) << shift
		shift += 7
	}

	var currentBaseHash string // Only populated for OBJ_REF_DELTA

	if objectType == OBJ_REF_DELTA {
		baseHashBytes := make([]byte, 20)
		_, err = io.ReadFull(file, baseHashBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read base hash for REF_DELTA: %w", err)
		}
		currentBaseHash = fmt.Sprintf("%x", baseHashBytes)
	} else if objectType == OBJ_OFS_DELTA {
		// Read the variable-length offset for OFS_DELTA
		// Note: The actual offset value isn't stored in the Object struct's BaseHash.
		// The caller (ParseModernPackfile) knows the base offset from its first pass.
		// We just need to consume these bytes from the file stream.
		var b byte = 0x80
		for (b & 0x80) != 0 {
			b, err = readByte(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read delta offset byte for OFS_DELTA: %w", err)
			}
			if (b & 0x80) == 0 {
				break
			}
		}
		// currentBaseHash remains empty for OFS_DELTA in the Object struct
	}

	// Initialize a zlib reader to decompress the object data
	zlibReader, err := zlib.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zlibReader.Close()

	// Read the decompressed object data
	data := make([]byte, 0, size) // Pre-allocate if size is reliable, or grow as needed
	// Ensure we read 'size' bytes of *decompressed* data.
	bytesReadSoFar := uint64(0)
	readBuf := make([]byte, 4096) // Temporary buffer for reading from zlib stream
	for bytesReadSoFar < size {
		n, rErr := zlibReader.Read(readBuf)
		if n > 0 {
			data = append(data, readBuf[:n]...)
			bytesReadSoFar += uint64(n)
		}
		if rErr == io.EOF {
			break // EOF is expected once all data is decompressed
		}
		if rErr != nil {
			return nil, fmt.Errorf("failed to read object data via zlib: %w", rErr)
		}
	}

	if bytesReadSoFar != size {
		return nil, fmt.Errorf("decompressed data size mismatch: expected %d, got %d for type %s at offset %d",
			size, bytesReadSoFar, typeToString(objectType), startPos)
	}

	return &Object{
		// Hash will be filled in later by the caller for non-delta/resolved objects
		Type:     objectType,      // Actual type (OBJ_BLOB, OBJ_REF_DELTA, etc.)
		Data:     data,            // Decompressed data (or delta instructions)
		BaseHash: currentBaseHash, // Populated only for OBJ_REF_DELTA
	}, nil
}

// readByte reads a single byte from the file
func readByte(file *os.File) (byte, error) {
	buf := make([]byte, 1)
	n, err := file.Read(buf)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return buf[0], nil
}

// calculateObjectHash calculates a hash for an object
func calculateObjectHash(objType ObjectType, data []byte) string {
	// Create the object header (e.g., "blob 12345\0")
	var typeStr string
	switch objType {
	case OBJ_COMMIT:
		typeStr = "commit"
	case OBJ_TREE:
		typeStr = "tree"
	case OBJ_BLOB:
		typeStr = "blob"
	case OBJ_TAG:
		typeStr = "tag"
	default:
		// This should ideally not happen if types are validated upstream
		// or all known types are handled. Returning an empty string
		// or panicking might be options depending on desired robustness.
		fmt.Printf("Warning: calculateObjectHash called with unknown object type: %d\n", objType)
		// Fallback to a non-standard string to avoid collision, but this is an error condition.
		typeStr = fmt.Sprintf("unknown_type_%d", objType)
	}

	header := fmt.Sprintf("%s %d\x00", typeStr, len(data))

	// Calculate SHA-1 hash of the entire content including header
	h := sha1.New()
	h.Write([]byte(header))
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil))
}
