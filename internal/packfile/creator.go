package packfile

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
)

// CreatePackfileFromObjects creates a binary packfile from a list of objects
// This function handles in-memory objects rather than repository paths
func CreatePackfileFromObjects(objects []Object) ([]byte, error) {
	// Calculate the total size needed for the packfile
	totalSize := 4 // 4 bytes for number of objects
	for _, obj := range objects {
		totalSize += hashLength    // hash
		totalSize += 4             // data length
		totalSize += 1             // type
		totalSize += len(obj.Data) // data
	}

	// Create the packfile
	packfile := make([]byte, totalSize)

	// Write number of objects
	binary.BigEndian.PutUint32(packfile[0:4], uint32(len(objects)))
	offset := 4

	// Write each object
	for _, obj := range objects {
		// Write hash
		copy(packfile[offset:offset+hashLength], []byte(obj.Hash))
		offset += hashLength

		// Write data length (including type byte)
		dataLen := len(obj.Data) + 1
		binary.BigEndian.PutUint32(packfile[offset:offset+4], uint32(dataLen))
		offset += 4

		// Write type
		packfile[offset] = byte(obj.Type)
		offset++

		// Write data
		copy(packfile[offset:offset+len(obj.Data)], obj.Data)
		offset += len(obj.Data)
	}

	return packfile, nil
}

// CreateModernPackfile creates a modern packfile with deltas and compression
func CreateModernPackfile(objects []Object, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create packfile: %w", err)
	}
	defer file.Close()

	// Track object offsets for the index
	offsets := make(map[string]uint64)

	// Write header (signature, version, number of objects)
	header := PackFileHeader{
		Signature:  [4]byte{'P', 'A', 'C', 'K'},
		Version:    2,
		NumObjects: uint32(len(objects)),
	}

	// Write header
	if err := binary.Write(file, binary.BigEndian, &header); err != nil {
		return fmt.Errorf("failed to write packfile header: %w", err)
	}

	// Write each object and record its offset
	for _, obj := range objects {
		// Get current position for object offset
		pos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("failed to get file position: %w", err)
		}

		// Record the offset for this object
		offsets[obj.Hash] = uint64(pos)

		// headerType will be obj.Type unless it's an offset delta that needs special handling (not implemented here)
		headerType := obj.Type
		currentObjectData := obj.Data // Data to be written (delta data for deltas)
		var baseHashForWriting string // Binary hash string of the base object for REF_DELTA

		// Special handling for delta objects
		// As per changes in delta.go, OptimizeObjects now produces Objects with Type=OBJ_REF_DELTA and BaseHash set.
		if obj.Type == OBJ_REF_DELTA {
			headerType = OBJ_REF_DELTA // This is already obj.Type, but explicit for clarity
			if obj.BaseHash == "" {
				// This should not happen if OptimizeObjects worked correctly
				return fmt.Errorf("critical: OBJ_REF_DELTA object %s has empty BaseHash", obj.Hash)
			}
			baseHashForWriting = obj.BaseHash
			// obj.Data is already just the delta instructions, no stripping needed.
		} else if obj.Type == OBJ_OFS_DELTA {
			// Placeholder: OFS_DELTA would also set headerType = OBJ_OFS_DELTA
			// And would need to write the offset differently instead of a base hash.
			// currentObjectData would be obj.Data (delta instructions)
			// For now, we only expect OBJ_REF_DELTA from OptimizeObjects
			return fmt.Errorf("OBJ_OFS_DELTA handling not fully implemented in CreateModernPackfile: %s", obj.Hash)
		}

		// Write object header (type and size)
		// For deltas, obj.Data is the delta payload. For non-deltas, it's the raw object data.
		if err := writeObjectHeader(file, headerType, uint64(len(currentObjectData))); err != nil {
			return fmt.Errorf("failed to write object header for %s: %w", obj.Hash, err)
		}

		// For REF_DELTA objects, write the base object hash reference (20 bytes)
		if headerType == OBJ_REF_DELTA {
			baseHashBytes, err := hex.DecodeString(baseHashForWriting)
			if err != nil || len(baseHashBytes) != 20 {
				return fmt.Errorf("invalid BaseHash '%s' for OBJ_REF_DELTA object %s: %w", baseHashForWriting, obj.Hash, err)
			}

			if _, err := file.Write(baseHashBytes); err != nil {
				return fmt.Errorf("failed to write base hash for %s: %w", obj.Hash, err)
			}
		}

		// Compress and write object data
		compressedWriter := zlib.NewWriter(file)
		if _, err := compressedWriter.Write(currentObjectData); err != nil {
			compressedWriter.Close()
			return fmt.Errorf("failed to write compressed data for %s: %w", obj.Hash, err)
		}
		if err := compressedWriter.Close(); err != nil {
			return fmt.Errorf("failed to close compressed writer for %s: %w", obj.Hash, err)
		}
	}

	// Calculate and write packfile checksum
	endPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get current file position: %w", err)
	}

	// Move back to the beginning of the file to calculate checksum
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to beginning of file: %w", err)
	}

	// Read the entire file content for checksum calculation
	content := make([]byte, endPos)
	if _, err := io.ReadFull(file, content); err != nil {
		return fmt.Errorf("failed to read file content for checksum: %w", err)
	}

	// Calculate SHA-1 checksum
	h := sha1.New()
	h.Write(content)
	checksum := h.Sum(nil)

	// Move back to the end to write checksum
	if _, err := file.Seek(endPos, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	// Write the SHA-1 checksum (20 bytes)
	if _, err := file.Write(checksum); err != nil {
		return fmt.Errorf("failed to write packfile checksum: %w", err)
	}

	// Create index file
	indexPath := outputPath + ".idx"
	if err := createPackIndex(indexPath, offsets, objects); err != nil {
		return fmt.Errorf("failed to create index file: %w", err)
	}

	return nil
}

// writeObjectHeader writes the packfile object header in Git format
// Uses a variable-length encoding for the size and includes type in the first byte
func writeObjectHeader(file *os.File, objType ObjectType, size uint64) error {
	// First byte: high 3 bits are type, low 4 bits are first chunk of size, bit 7 is continuation bit
	firstByte := byte((uint8(objType) << 4) & 0x70) // Type in bits 4-6

	// Encode size using variable-length encoding
	// First 4 bits of size go in the low 4 bits of the first byte
	firstByte |= byte(size & 0x0F) // Size bits 0-3

	// If the size requires more bytes, set the continuation bit
	if size >= 0x10 { // If size doesn't fit in 4 bits
		firstByte |= 0x80 // Set MSB (continuation bit)
	}

	// Write the first byte
	if _, err := file.Write([]byte{firstByte}); err != nil {
		return fmt.Errorf("failed to write object header first byte: %w", err)
	}

	// Write additional size bytes if needed, 7 bits at a time, with continuation bit
	remainingSize := size >> 4
	for remainingSize > 0 {
		// Next 7 bits of the size
		nextByte := byte(remainingSize & 0x7F)

		// If there are more bits after this, set the continuation bit
		remainingSize >>= 7
		if remainingSize > 0 {
			nextByte |= 0x80
		}

		// Write this byte
		if _, err := file.Write([]byte{nextByte}); err != nil {
			return fmt.Errorf("failed to write object header size byte: %w", err)
		}
	}

	return nil
}

// createPackIndex creates a Git-compatible index file for a packfile
// Following the v2 index format specification
func createPackIndex(indexPath string, offsets map[string]uint64, objects []Object) error {
	file, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("failed to create index file: %w", err)
	}
	defer file.Close()

	// Convert objects to sorted entries for the index
	type indexEntry struct {
		hash    []byte     // Binary hash
		offset  uint64     // Offset in pack file
		objType ObjectType // Object type
		crc32   uint32     // CRC32 checksum (optional)
	}

	entries := make([]indexEntry, 0, len(objects))
	for _, obj := range objects {
		offset, ok := offsets[obj.Hash]
		if !ok {
			continue // Skip objects not in packfile
		}

		// Convert hex hash to binary
		hashBytes, err := hex.DecodeString(obj.Hash)
		if err != nil || len(hashBytes) != 20 {
			return fmt.Errorf("invalid hash %s: %w", obj.Hash, err)
		}

		entries = append(entries, indexEntry{
			hash:    hashBytes,
			offset:  offset,
			objType: obj.Type,
			crc32:   0, // We're not tracking CRC32 for now
		})
	}

	// Sort entries by hash
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].hash, entries[j].hash) < 0
	})

	// Write index header: signature + version
	header := [8]byte{'\377', 't', 'O', 'c', 0, 0, 0, 2} // "\377tOc" + version 2
	if _, err := file.Write(header[:]); err != nil {
		return fmt.Errorf("failed to write index header: %w", err)
	}

	// Build fanout table (256 entries)
	fanout := make([]uint32, 256)

	// Count objects with each first byte
	for _, entry := range entries {
		firstByte := entry.hash[0]
		fanout[firstByte]++
	}

	// Convert to cumulative counts
	for i := 1; i < 256; i++ {
		fanout[i] += fanout[i-1]
	}

	// Write fanout table (256 uint32 values)
	for _, count := range fanout {
		if err := binary.Write(file, binary.BigEndian, count); err != nil {
			return fmt.Errorf("failed to write fanout table: %w", err)
		}
	}

	// Write object names (sorted by hash)
	for _, entry := range entries {
		if _, err := file.Write(entry.hash); err != nil {
			return fmt.Errorf("failed to write object hash: %w", err)
		}
	}

	// Write CRC32 values (4 bytes per object)
	for _, entry := range entries {
		if err := binary.Write(file, binary.BigEndian, entry.crc32); err != nil {
			return fmt.Errorf("failed to write CRC32: %w", err)
		}
	}

	// Write offsets (4 or 8 bytes per object)
	largeOffsets := make([]uint64, 0)

	for _, entry := range entries {
		if entry.offset < (1 << 31) {
			// Regular offset (31 bits)
			if err := binary.Write(file, binary.BigEndian, uint32(entry.offset)); err != nil {
				return fmt.Errorf("failed to write offset: %w", err)
			}
		} else {
			// Large offset - mark with MSB set and index into large offset table
			largeOffsetIndex := uint32(len(largeOffsets) | (1 << 31))
			if err := binary.Write(file, binary.BigEndian, largeOffsetIndex); err != nil {
				return fmt.Errorf("failed to write large offset index: %w", err)
			}
			largeOffsets = append(largeOffsets, entry.offset)
		}
	}

	// Write large offsets table if needed
	for _, offset := range largeOffsets {
		if err := binary.Write(file, binary.BigEndian, offset); err != nil {
			return fmt.Errorf("failed to write large offset: %w", err)
		}
	}

	// Calculate and write packfile checksum (copy from the packfile)
	packfilePath := indexPath[:len(indexPath)-4] // Remove .idx
	packfileChecksum, err := getPackfileChecksum(packfilePath)
	if err != nil {
		return fmt.Errorf("failed to get packfile checksum: %w", err)
	}

	if _, err := file.Write(packfileChecksum); err != nil {
		return fmt.Errorf("failed to write packfile checksum: %w", err)
	}

	// Calculate and write index checksum
	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get file position: %w", err)
	}

	// Go back to start to calculate the checksum of the index
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to file start: %w", err)
	}

	content := make([]byte, currentPos)
	if _, err := file.Read(content); err != nil {
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Calculate checksum
	h := sha1.New()
	h.Write(content)
	indexChecksum := h.Sum(nil)

	// Move back to end to write checksum
	if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to file end: %w", err)
	}

	// Write index checksum
	if _, err := file.Write(indexChecksum); err != nil {
		return fmt.Errorf("failed to write index checksum: %w", err)
	}

	return nil
}

// getPackfileChecksum reads the SHA-1 checksum from the end of a packfile
func getPackfileChecksum(packfilePath string) ([]byte, error) {
	file, err := os.Open(packfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open packfile: %w", err)
	}
	defer file.Close()

	// Seek to 20 bytes from the end to get the SHA-1 checksum
	if _, err := file.Seek(-20, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("failed to seek to checksum: %w", err)
	}

	// Read the 20-byte SHA-1 checksum
	checksum := make([]byte, 20)
	if _, err := io.ReadFull(file, checksum); err != nil {
		return nil, fmt.Errorf("failed to read checksum: %w", err)
	}

	return checksum, nil
}
