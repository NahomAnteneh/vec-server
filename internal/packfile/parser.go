package packfile

import (
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

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
		// Determine if we're dealing with SHA-1 or SHA-256 based on the packfile format
		hashLen := 40 // Default to SHA-1 hex format (40 chars)
		if offset+hashLen+4 > len(packfile) {
			return nil, errors.New("packfile format error: incomplete object header")
		}

		hashBytes := packfile[offset : offset+hashLen]
		hash := string(hashBytes) // Assumes hash is stored as a hex string.
		offset += hashLen

		// Try to populate HashBytes for compatibility
		var hashBinaryBytes [hashLength]byte
		if len(hash) == 40 { // SHA-1
			// For SHA-1, we'll pad it to match our internal format
			sha1Bytes, err := hex.DecodeString(hash)
			if err == nil && len(sha1Bytes) == 20 {
				// Pad with zeros to match SHA-256 length
				copy(hashBinaryBytes[:], sha1Bytes)
			}
		} else if len(hash) == 64 { // SHA-256
			binaryBytes, err := hex.DecodeString(hash)
			if err == nil && len(binaryBytes) == 32 {
				copy(hashBinaryBytes[:], binaryBytes)
			}
		}

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
			Hash:      hash,
			HashBytes: hashBinaryBytes,
			Type:      objType,
			Data:      data,
			Size:      uint64(len(data)),
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

	// Store information about each object
	type objectInfo struct {
		offset        int64            // File offset of object
		isDelta       bool             // Whether this is a delta object
		baseHash      string           // Base object hash (for REF_DELTA)
		basePos       int64            // Base object position (for OFS_DELTA)
		baseHashBytes [hashLength]byte // Base hash in binary format
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

			// Check if we're using SHA-1 (20 bytes) or SHA-256 (32 bytes)
			// We'll try to detect by reading first and checking the zlib header
			pos, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, fmt.Errorf("failed to get current position: %w", err)
			}

			// Try SHA-1 first (most common)
			baseHashBytes20 := make([]byte, 20) // SHA-1 is 20 bytes
			_, err = io.ReadFull(file, baseHashBytes20)
			if err != nil {
				return nil, fmt.Errorf("failed to read base hash for REF_DELTA: %w", err)
			}

			// Check if what follows is a valid zlib header
			zlibHeader := make([]byte, 2)
			_, err = io.ReadFull(file, zlibHeader)
			if err != nil {
				return nil, fmt.Errorf("failed to read zlib header: %w", err)
			}

			// Seek back to prepare for actual read
			_, err = file.Seek(pos, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("failed to reset position: %w", err)
			}

			// Determine hash format based on zlib header
			// Valid zlib header starts with 0x78
			if zlibHeader[0] == 0x78 {
				// It's SHA-1 format
				_, err = io.ReadFull(file, baseHashBytes20)
				if err != nil {
					return nil, fmt.Errorf("failed to re-read SHA-1 base hash: %w", err)
				}
				info.baseHash = fmt.Sprintf("%x", baseHashBytes20)

				// Create a byte array for the base hash
				var baseHashBinary [hashLength]byte
				copy(baseHashBinary[:], baseHashBytes20)
				info.baseHashBytes = baseHashBinary
			} else {
				// It's likely SHA-256 format (32 bytes)
				baseHashBytes32 := make([]byte, 32)
				_, err = io.ReadFull(file, baseHashBytes32)
				if err != nil {
					return nil, fmt.Errorf("failed to read SHA-256 base hash: %w", err)
				}
				info.baseHash = fmt.Sprintf("%x", baseHashBytes32)

				// Store the hash bytes
				var baseHashBinary [hashLength]byte
				copy(baseHashBinary[:], baseHashBytes32)
				info.baseHashBytes = baseHashBinary
			}
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

	for objIndex, info := range objectInfos {
		if !info.isDelta {
			// Not a delta, read normally
			_, err = file.Seek(info.offset, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("failed to seek to object at offset %d: %w", info.offset, err)
			}

			obj, err := readPackObject(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read object at offset %d: %w", info.offset, err)
			}

			// Calculate object hash
			hash := calculateObjectHash(obj.Type, obj.Data)
			hashBytes, _ := hexToBytes(hash)

			obj.Hash = hash
			obj.HashBytes = hashBytes
			obj.Offset = info.offset

			objects = append(objects, *obj)
			objectsByOffset[info.offset] = &objects[len(objects)-1]
		} else {
			// This is a delta object, we'll resolve it in the third pass
			deltaObjects = append(deltaObjects, struct {
				objIndex uint64
				info     objectInfo
			}{objIndex, info})
		}
	}

	// Sort delta objects by dependency order
	sort.Slice(deltaObjects, func(i, j int) bool {
		infoI := deltaObjects[i].info
		infoJ := deltaObjects[j].info

		// Handle ref deltas vs offset deltas
		if infoI.baseHash != "" && infoJ.baseHash == "" {
			return true // Ref deltas before offset deltas
		}
		if infoI.baseHash == "" && infoJ.baseHash != "" {
			return false
		}

		// For offset deltas, order by base position
		if infoI.baseHash == "" {
			return infoI.basePos < infoJ.basePos
		}

		// For ref deltas with the same base, use original index
		return deltaObjects[i].objIndex < deltaObjects[j].objIndex
	})

	// Third pass: resolve delta objects
	for _, delta := range deltaObjects {
		info := delta.info

		_, err = file.Seek(info.offset, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek to delta object at offset %d: %w", info.offset, err)
		}

		deltaObj, err := readPackObject(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read delta object at offset %d: %w", info.offset, err)
		}

		// Find base object
		var baseObj *Object
		if info.baseHash != "" {
			// Reference delta - find base by hash
			for i := range objects {
				if objects[i].Hash == info.baseHash {
					baseObj = &objects[i]
					break
				}
			}
		} else {
			// Offset delta - find base by offset
			baseObj = objectsByOffset[info.basePos]
		}

		if baseObj == nil {
			return nil, fmt.Errorf("base object not found for delta at offset %d", info.offset)
		}

		// Apply delta to base object
		resultData, err := applyDelta(baseObj.Data, deltaObj.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to apply delta at offset %d: %w", info.offset, err)
		}

		// Create resolved object (inherits type from base)
		resultObj := Object{
			Type:     baseObj.Type,
			Data:     resultData,
			Offset:   info.offset,
			Size:     uint64(len(resultData)),
			BaseHash: info.baseHash,
		}

		// Calculate hash for the resolved object
		resultObj.Hash = calculateObjectHash(resultObj.Type, resultObj.Data)
		resultObj.HashBytes, _ = hexToBytes(resultObj.Hash)

		// Add to objects list
		objects = append(objects, resultObj)
		objectsByOffset[info.offset] = &objects[len(objects)-1]
	}

	return objects, nil
}

// readPackObject reads a single object from a packfile
func readPackObject(file *os.File) (*Object, error) {
	startPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to get current position: %w", err)
	}

	// Read the first byte which contains the type and part of the size
	headerByte, err := readByte(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read object header byte: %w", err)
	}

	// Extract the type from bits 4-6
	objectType := ObjectType((headerByte >> 4) & 0x7)

	// Extract the size (starts in the lower 4 bits)
	size := uint64(headerByte & 0x0F)
	shift := uint(4)

	// Read the variable-length size
	for headerByte&0x80 != 0 {
		headerByte, err = readByte(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read size byte: %w", err)
		}
		size |= uint64(headerByte&0x7F) << shift
		shift += 7
	}

	// For delta objects, we need to read the base reference
	var currentBaseHash string
	var baseHashBytes [hashLength]byte

	if objectType == OBJ_REF_DELTA {
		// Check if we're using SHA-1 (20 bytes) or SHA-256 (32 bytes)
		// We'll try to detect by reading first and checking the zlib header
		pos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get current position: %w", err)
		}

		// Try SHA-1 first (most common)
		baseHashBytes20 := make([]byte, 20) // SHA-1 is 20 bytes
		_, err = io.ReadFull(file, baseHashBytes20)
		if err != nil {
			return nil, fmt.Errorf("failed to read base hash for REF_DELTA: %w", err)
		}

		// Check if what follows is a valid zlib header
		zlibHeader := make([]byte, 2)
		_, err = io.ReadFull(file, zlibHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to read zlib header: %w", err)
		}

		// Seek back to prepare for actual read
		_, err = file.Seek(pos, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to reset position: %w", err)
		}

		// Determine hash format based on zlib header
		// Valid zlib header starts with 0x78
		if zlibHeader[0] == 0x78 {
			// It's SHA-1 format
			_, err = io.ReadFull(file, baseHashBytes20)
			if err != nil {
				return nil, fmt.Errorf("failed to re-read SHA-1 base hash: %w", err)
			}
			currentBaseHash = fmt.Sprintf("%x", baseHashBytes20)

			// Convert to internal format
			copy(baseHashBytes[:], baseHashBytes20)
		} else {
			// It's likely SHA-256 format (32 bytes)
			baseHashBytes32 := make([]byte, 32)
			_, err = io.ReadFull(file, baseHashBytes32)
			if err != nil {
				return nil, fmt.Errorf("failed to read SHA-256 base hash: %w", err)
			}
			currentBaseHash = fmt.Sprintf("%x", baseHashBytes32)
			copy(baseHashBytes[:], baseHashBytes32)
		}
	} else if objectType == OBJ_OFS_DELTA {
		// Read the variable-length offset for OFS_DELTA
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
			size, bytesReadSoFar, TypeToString(objectType), startPos)
	}

	return &Object{
		Type:          objectType,
		Data:          data,
		BaseHash:      currentBaseHash,
		BaseHashBytes: baseHashBytes,
		Size:          size,
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

	// Calculate SHA-256 hash of the entire content including header
	h := sha256.New()
	h.Write([]byte(header))
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil))
}
