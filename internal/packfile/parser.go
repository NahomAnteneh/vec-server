package packfile

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
)

// parsePackfileReader parses a packfile from a reader
func parsePackfileReader(r io.Reader, hashLength int) ([]Object, error) {
	// Validate hashLength
	if hashLength <= 0 {
		return nil, fmt.Errorf("invalid hash length: %d", hashLength)
	}

	// First read the entire content into a buffer to avoid seeking issues with non-file readers
	var packData bytes.Buffer
	if _, err := io.Copy(&packData, r); err != nil {
		return nil, fmt.Errorf("failed to read packfile content: %w", err)
	}

	// Convert to a byte reader for easier access
	buf := bytes.NewReader(packData.Bytes())

	// Read and verify header
	var header PackFileHeader
	if err := binary.Read(buf, binary.BigEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read packfile header: %w", err)
	}
	if string(header.Signature[:]) != "PACK" || header.Version != 2 {
		return nil, fmt.Errorf("invalid packfile header: signature=%s, version=%d", string(header.Signature[:]), header.Version)
	}

	// Store object metadata
	type objectInfo struct {
		offset   int64
		isDelta  bool
		baseHash string
		basePos  int64
	}
	objectInfos := make(map[uint64]objectInfo, header.NumObjects)
	objectsByOffset := make(map[int64]*Object)

	// First pass: collect metadata
	if _, err := buf.Seek(12, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start of objects: %w", err)
	}

	// Check for zero objects case
	if header.NumObjects == 0 {
		return []Object{}, nil
	}

	for i := uint32(0); i < header.NumObjects; i++ {
		pos, err := buf.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get position for object %d: %w", i, err)
		}

		headerByte, err := readByte(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read header byte for object %d: %w", i, err)
		}
		objType := ObjectType((headerByte >> 4) & 0x7)

		// Validate object type
		if objType < OBJ_COMMIT || (objType > OBJ_TAG && objType != OBJ_OFS_DELTA && objType != OBJ_REF_DELTA) {
			return nil, fmt.Errorf("invalid object type %d for object %d", objType, i)
		}

		// Decode size
		size := uint64(headerByte & 0x0F)
		shift := uint(4)
		for headerByte&0x80 != 0 {
			headerByte, err = readByte(buf)
			if err != nil {
				return nil, fmt.Errorf("failed to read size byte for object %d: %w", i, err)
			}
			size |= uint64(headerByte&0x7F) << shift
			shift += 7

			// Prevent infinite loop with corrupted data
			if shift > 64 {
				return nil, fmt.Errorf("corrupted size encoding for object %d", i)
			}
		}

		info := objectInfo{offset: pos}
		if objType == OBJ_REF_DELTA {
			info.isDelta = true
			baseHashBytes := make([]byte, hashLength)
			if _, err := io.ReadFull(buf, baseHashBytes); err != nil {
				return nil, fmt.Errorf("failed to read base hash for object %d: %w", i, err)
			}
			info.baseHash = hex.EncodeToString(baseHashBytes)
		} else if objType == OBJ_OFS_DELTA {
			info.isDelta = true
			var baseOffset uint64
			var b byte = 0x80
			var j uint
			for b&0x80 != 0 {
				b, err = readByte(buf)
				if err != nil {
					return nil, fmt.Errorf("failed to read delta offset for object %d: %w", i, err)
				}
				baseOffset |= uint64(b&0x7F) << (j * 7)
				j++

				// Prevent infinite loop with corrupted data
				if j > 10 { // Reasonable limit for offset encoding
					return nil, fmt.Errorf("corrupted delta offset encoding for object %d", i)
				}
			}
			info.basePos = pos - int64(baseOffset)

			// Validate base position
			if info.basePos < 0 {
				return nil, fmt.Errorf("invalid negative base position %d for object %d", info.basePos, i)
			}
		}
		objectInfos[uint64(i)] = info

		// Skip over the compressed data
		zr, err := zlib.NewReader(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader for object %d during metadata scan: %w", i, err)
		}
		defer zr.Close()

		// Consume the data for the current object
		if _, copyErr := io.Copy(io.Discard, zr); copyErr != nil {
			// zr.Close() will be called by defer
			return nil, fmt.Errorf("failed to skip (io.Copy) compressed data for object %d: %w", i, copyErr)
		}
	}

	// Second pass: read non-delta objects
	var objects []Object
	var deltaObjects []struct {
		objIndex uint64
		info     objectInfo
	}

	for objIndex, info := range objectInfos {
		if !info.isDelta {
			if _, err := buf.Seek(info.offset, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to object %d: %w", objIndex, err)
			}

			obj, err := readPackObjectFromReader(buf, hashLength)
			if err != nil {
				return nil, fmt.Errorf("failed to read object %d: %w", objIndex, err)
			}

			hash := calculateObjectHash(obj.Type, obj.Data)
			hashBytes, _ := hexToBytes(hash, hashLength)
			obj.Hash = hash
			obj.HashBytes = hashBytes
			obj.Offset = info.offset
			objects = append(objects, *obj)
			objectsByOffset[info.offset] = obj
		} else {
			deltaObjects = append(deltaObjects, struct {
				objIndex uint64
				info     objectInfo
			}{objIndex, info})
		}
	}

	// Sort delta objects to resolve dependencies correctly
	sort.Slice(deltaObjects, func(i, j int) bool {
		infoI, infoJ := deltaObjects[i].info, deltaObjects[j].info
		if infoI.baseHash != "" && infoJ.baseHash == "" {
			return true
		}
		if infoI.baseHash == "" && infoJ.baseHash != "" {
			return false
		}
		if infoI.baseHash == "" {
			return infoI.basePos < infoJ.basePos
		}
		return deltaObjects[i].objIndex < deltaObjects[j].objIndex
	})

	// Check for direct circular references before processing
	refDeltaHashes := make(map[string]int) // hash -> index in deltaObjects

	// First map all REF_DELTA hashes we know about
	for i, obj := range objects {
		if len(obj.Hash) > 0 {
			refDeltaHashes[obj.Hash] = i
		}
	}

	// Then check if any delta references another delta as its base
	for _, d := range deltaObjects {
		info := d.info
		if info.baseHash != "" {
			// If this delta references a hash that's part of another delta,
			// and that delta references back to this one, it's circular
			if baseIndex, exists := refDeltaHashes[info.baseHash]; exists {
				baseObj := objects[baseIndex]
				// If the base is also a delta and references this hash, it's a cycle
				if (baseObj.Type == OBJ_REF_DELTA || baseObj.Type == OBJ_OFS_DELTA) &&
					baseObj.BaseHash == deltaObjects[d.objIndex].info.baseHash {
					return nil, fmt.Errorf("circular delta dependency detected between %s and %s",
						info.baseHash, deltaObjects[d.objIndex].info.baseHash)
				}
			}
		}
	}

	// Third pass: resolve deltas
	// Keep track of resolved objects and visited offsets to detect cycles
	processedOffsets := make(map[int64]bool)
	visitedOffsets := make(map[int64]bool)
	visitedHashes := make(map[string]bool) // Track hashes to detect REF_DELTA cycles

	// We don't want to allow infinite delta chains
	const maxDeltaDepth = 10

	// Process each delta object
	for _, d := range deltaObjects {
		info := d.info

		// Check for circular dependencies via offset
		if visitedOffsets[info.offset] {
			return nil, fmt.Errorf("circular delta dependency detected at offset %d", info.offset)
		}

		// Check for circular dependencies via hash
		if info.baseHash != "" && visitedHashes[info.baseHash] {
			return nil, fmt.Errorf("circular delta dependency detected with base hash %s", info.baseHash)
		}

		// Mark this delta as visited for cycle detection
		visitedOffsets[info.offset] = true
		if info.baseHash != "" {
			visitedHashes[info.baseHash] = true
		}

		// Seek to delta object
		var seekErr error
		_, seekErr = buf.Seek(info.offset, io.SeekStart)
		if seekErr != nil {
			return nil, fmt.Errorf("failed to seek to delta at offset %d: %w", info.offset, seekErr)
		}

		// Read delta object
		deltaObj, readErr := readPackObjectFromReader(buf, hashLength)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read delta at offset %d: %w", info.offset, readErr)
		}

		if !(deltaObj.Type == OBJ_REF_DELTA || deltaObj.Type == OBJ_OFS_DELTA) {
			return nil, fmt.Errorf("expected delta at offset %d, got %s", info.offset, TypeToString(deltaObj.Type))
		}

		// Find base object
		var baseObj *Object
		if info.baseHash != "" {
			// REF_DELTA - find by hash
			for i := range objects {
				if objects[i].Hash == info.baseHash {
					baseObj = &objects[i]
					break
				}
			}
		} else {
			// OFS_DELTA - find by offset
			baseObj = objectsByOffset[info.basePos]
		}

		if baseObj == nil {
			return nil, fmt.Errorf("base object not found for delta at offset %d (baseHash=%s, basePos=%d)",
				info.offset, info.baseHash, info.basePos)
		}

		// Apply delta
		resultData, err := applyDelta(baseObj.Data, deltaObj.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to apply delta at offset %d: %w", info.offset, err)
		}

		// Create result object
		resultObj := Object{
			Type:   baseObj.Type,
			Data:   resultData,
			Offset: info.offset,
			Size:   uint64(len(resultData)),
		}

		hash := calculateObjectHash(resultObj.Type, resultObj.Data)
		hashBytes, _ := hexToBytes(hash, hashLength)
		resultObj.Hash = hash
		resultObj.HashBytes = hashBytes

		// Add to collections
		objects = append(objects, resultObj)
		objectsByOffset[info.offset] = &objects[len(objects)-1]

		// Mark this delta as processed
		processedOffsets[info.offset] = true

		// Clear from visited since we're done with this path
		delete(visitedOffsets, info.offset)
	}

	return objects, nil
}

// Helper to read a single byte
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := r.Read(b[:])
	return b[0], err
}

// readPackObjectFromReader reads a single object from a generic reader
func readPackObjectFromReader(r io.Reader, hashLength int) (*Object, error) {
	if hashLength <= 0 {
		return nil, fmt.Errorf("invalid hash length: %d", hashLength)
	}

	headerByte, err := readByte(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read header byte: %w", err)
	}

	objType := ObjectType((headerByte >> 4) & 0x7)

	// Validate object type
	if objType < OBJ_COMMIT || (objType > OBJ_TAG && objType != OBJ_OFS_DELTA && objType != OBJ_REF_DELTA) {
		return nil, fmt.Errorf("invalid object type %d", objType)
	}

	size := uint64(headerByte & 0x0F)
	shift := uint(4)
	for headerByte&0x80 != 0 {
		headerByte, err = readByte(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read size byte: %w", err)
		}
		size |= uint64(headerByte&0x7F) << shift
		shift += 7

		// Prevent infinite loop with corrupted data
		if shift > 64 { // Reasonable limit for size encoding
			return nil, fmt.Errorf("corrupted size encoding")
		}
	}

	var baseHash string
	var baseHashBytes []byte

	if objType == OBJ_REF_DELTA {
		baseHashBytes = make([]byte, hashLength)
		if _, err := io.ReadFull(r, baseHashBytes); err != nil {
			return nil, fmt.Errorf("failed to read base hash: %w", err)
		}
		baseHash = hex.EncodeToString(baseHashBytes)
	} else if objType == OBJ_OFS_DELTA {
		var b byte = 0x80
		var offset uint64
		var j uint

		for b&0x80 != 0 {
			b, err = readByte(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read delta offset byte: %w", err)
			}
			offset |= uint64(b&0x7F) << (j * 7)
			j++

			// Prevent infinite loop
			if j > 10 {
				return nil, fmt.Errorf("corrupted delta offset encoding")
			}
		}
	}

	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zr.Close()

	objData, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	obj := &Object{
		Type:          objType,
		Size:          size,
		Data:          objData,
		BaseHash:      baseHash,
		BaseHashBytes: baseHashBytes,
	}

	return obj, nil
}

// readPackObject reads a single object from a file
func readPackObject(f *os.File, hashLength int) (*Object, error) {
	if f == nil {
		return nil, fmt.Errorf("nil file handle")
	}
	return readPackObjectFromReader(f, hashLength)
}

func calculateObjectHash(objType ObjectType, data []byte) string {
	var prefix string
	switch objType {
	case OBJ_COMMIT:
		prefix = "commit"
	case OBJ_TREE:
		prefix = "tree"
	case OBJ_BLOB:
		prefix = "blob"
	case OBJ_TAG:
		prefix = "tag"
	default:
		prefix = "blob" // Default to blob for unknown types
	}

	header := fmt.Sprintf("%s %d\x00", prefix, len(data))
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil))
}
