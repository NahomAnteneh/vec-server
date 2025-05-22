package packfile

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
)

// ReadPackIndex reads a packfile index from the given path
func ReadPackIndex(indexPath string) (*PackfileIndex, error) {
	file, err := os.Open(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open index file: %w", err)
	}
	defer file.Close()

	// Read and verify header (8 bytes: 4 for signature, 4 for version)
	headerBytes := make([]byte, 8)
	if _, err := io.ReadFull(file, headerBytes); err != nil {
		return nil, fmt.Errorf("failed to read index header: %w", err)
	}
	if string(headerBytes[:4]) != "\377tOc" {
		return nil, errors.New("invalid index file: bad signature")
	}
	version := binary.BigEndian.Uint32(headerBytes[4:])
	if version != 2 {
		return nil, fmt.Errorf("unsupported index version: %d", version)
	}

	// Read fanout table (256 entries * 4 bytes/entry = 1024 bytes)
	fanoutTable := make([]uint32, 256)
	if err := binary.Read(file, binary.BigEndian, fanoutTable); err != nil {
		return nil, fmt.Errorf("failed to read fanout table: %w", err)
	}
	numObjects := uint32(fanoutTable[255]) // Total number of objects from last fanout entry

	// Prepare to read main tables
	objectHashes := make([][]byte, numObjects) // Store raw SHA-256 byte slices
	objectCRCs := make([]uint32, numObjects)
	objectOffsets := make([]uint64, numObjects)
	packIndexEntries := make(map[string]PackIndexEntry, numObjects)

	// Read SHA-256 names (numObjects * 32 bytes/hash)
	for i := uint32(0); i < numObjects; i++ {
		objectHashes[i] = make([]byte, 32)
		if _, err := io.ReadFull(file, objectHashes[i]); err != nil {
			return nil, fmt.Errorf("failed to read SHA-256 #%d: %w", i, err)
		}
	}

	// Read CRC32 checksums (numObjects * 4 bytes/CRC)
	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(file, binary.BigEndian, &objectCRCs[i]); err != nil {
			return nil, fmt.Errorf("failed to read CRC32 #%d: %w", i, err)
		}
	}

	// Read offsets (numObjects * 4 bytes/offset for the primary offset table)
	// This table might contain 8-byte offsets if MSB is set, pointing to a separate large offset table.
	numLargeOffsets := 0
	tempOffsets := make([]uint32, numObjects)
	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(file, binary.BigEndian, &tempOffsets[i]); err != nil {
			return nil, fmt.Errorf("failed to read offset value #%d: %w", i, err)
		}
		if (tempOffsets[i] & 0x80000000) != 0 { // MSB is set, indicates large offset
			numLargeOffsets++
		}
	}

	// Read large offsets table if any (numLargeOffsets * 8 bytes/offset)
	largeOffsetsTable := make([]uint64, numLargeOffsets)
	if numLargeOffsets > 0 {
		for i := 0; i < numLargeOffsets; i++ {
			if err := binary.Read(file, binary.BigEndian, &largeOffsetsTable[i]); err != nil {
				return nil, fmt.Errorf("failed to read large offset #%d: %w", i, err)
			}
		}
	}

	// Populate final offsets and create PackIndexEntry map
	for i := uint32(0); i < numObjects; i++ {
		if (tempOffsets[i] & 0x80000000) != 0 { // MSB set, use large offset
			// The lower 31 bits of tempOffsets[i] is the index into largeOffsetsTable
			idxInLargeTable := tempOffsets[i] & 0x7FFFFFFF
			if idxInLargeTable >= uint32(len(largeOffsetsTable)) {
				return nil, fmt.Errorf("large offset index %d out of bounds for object #%d", idxInLargeTable, i)
			}
			objectOffsets[i] = largeOffsetsTable[idxInLargeTable]
		} else {
			objectOffsets[i] = uint64(tempOffsets[i])
		}

		hashHex := fmt.Sprintf("%x", objectHashes[i])
		packIndexEntries[hashHex] = PackIndexEntry{
			Offset: objectOffsets[i],
			CRC32:  objectCRCs[i],
			Type:   OBJ_NONE, // Type and Size are not in the index file; must be read from pack.
			Size:   0,        // Size is also not in the index file.
		}
	}

	// Read packfile checksum (32 bytes at the end of the index, before index checksum)
	packChecksum := make([]byte, 32)
	if _, err := io.ReadFull(file, packChecksum); err != nil {
		// Check for EOF, as some simple index files might omit this or the index checksum
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			fmt.Println("Warning: Could not read packfile checksum from index (EOF reached).")
			packChecksum = nil // Indicate it wasn't read
		} else {
			return nil, fmt.Errorf("failed to read packfile checksum: %w", err)
		}
	}

	// The final 20 bytes are the index file's own checksum. We don't store it in PackfileIndex struct.
	// We could read and verify it here if desired.

	return &PackfileIndex{
		Version:  version,
		Entries:  packIndexEntries,
		Checksum: packChecksum, // SHA-1 checksum of the corresponding packfile
	}, nil
}

// WritePackIndex writes a packfile index to the given path
func WritePackIndex(index *PackfileIndex, indexPath string) error {
	file, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("failed to create index file: %w", err)
	}
	defer file.Close()

	// Write header
	header := [8]byte{'\377', 't', 'O', 'c', 0, 0, 0, 2} // "\377tOc" + version 2
	if _, err := file.Write(header[:]); err != nil {
		return fmt.Errorf("failed to write index header: %w", err)
	}

	// Prepare data for fanout table, SHA-256 table, and offset table
	numObjects := uint32(len(index.Entries))
	fanout := make([]uint32, 256)
	hashes := make([]string, 0, numObjects)

	// Collect all SHA-256 values
	for hashHex := range index.Entries {
		hashes = append(hashes, hashHex)
	}

	// Sort SHA-256 values lexicographically
	sortHashes(hashes)

	// Build fanout table - count how many objects start with each byte value
	for _, hashHex := range hashes {
		// Convert first byte of hex string to byte value (two hex chars = one byte)
		if len(hashHex) >= 2 {
			val, err := strconv.ParseUint(hashHex[:2], 16, 8)
			if err != nil {
				return fmt.Errorf("invalid SHA-256 hex prefix %s: %w", hashHex[:2], err)
			}
			firstByteVal := byte(val)

			// Increment counters for this byte and all higher values
			for i := int(firstByteVal); i < 256; i++ {
				fanout[i]++
			}
		}
	}

	// Write fanout table
	for i := 0; i < 256; i++ {
		if err := binary.Write(file, binary.BigEndian, fanout[i]); err != nil {
			return fmt.Errorf("failed to write fanout table entry: %w", err)
		}
	}

	// Write SHA-256 table
	for _, hashHex := range hashes {
		// Convert hex string to bytes and write
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil {
			return fmt.Errorf("invalid SHA-256 hex string %s: %w", hashHex, err)
		}
		if _, err := file.Write(hashBytes); err != nil {
			return fmt.Errorf("failed to write SHA-256: %w", err)
		}
	}

	// Write CRC32 table (all zeros for simplicity)
	crc32 := make([]byte, numObjects*4)
	if _, err := file.Write(crc32); err != nil {
		return fmt.Errorf("failed to write CRC32 table: %w", err)
	}

	// Write offset table
	for _, hashHex := range hashes {
		entry := index.Entries[hashHex]

		// Check if we need a large offset
		if entry.Offset < (1 << 31) {
			// Regular offset
			offset := uint32(entry.Offset)
			if err := binary.Write(file, binary.BigEndian, offset); err != nil {
				return fmt.Errorf("failed to write offset: %w", err)
			}
		} else {
			// Large offset (not implemented for simplicity)
			return errors.New("large offsets not implemented")
		}
	}

	// Write pack checksum (all zeros for simplicity)
	packChecksum := make([]byte, 20)
	if _, err := file.Write(packChecksum); err != nil {
		return fmt.Errorf("failed to write pack checksum: %w", err)
	}

	// Write index checksum (all zeros for simplicity)
	indexChecksum := make([]byte, 20)
	if _, err := file.Write(indexChecksum); err != nil {
		return fmt.Errorf("failed to write index checksum: %w", err)
	}

	return nil
}

// VerifyPackIndex checks that all entries in the index are valid and present in the packfile
func VerifyPackIndex(indexPath, packfilePath string) error {
	// Read the index
	index, err := ReadPackIndex(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index: %w", err)
	}

	// Open the packfile
	packfile, err := os.Open(packfilePath)
	if err != nil {
		return fmt.Errorf("failed to open packfile: %w", err)
	}
	defer packfile.Close()

	// For each entry in the index, verify it points to a valid object in the packfile
	for sha1, entry := range index.Entries {
		// Seek to the object position
		_, err = packfile.Seek(int64(entry.Offset), io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to object %s: %w", sha1, err)
		}

		// Read just the object header to verify it exists
		// This is a simplified check; a real implementation would parse and verify the object
		headerByte := make([]byte, 1)
		_, err = packfile.Read(headerByte)
		if err != nil {
			return fmt.Errorf("failed to read object header for %s: %w", sha1, err)
		}
	}

	return nil
}

// sortHashes sorts SHA-256 hex strings in ascending order
func sortHashes(hashes []string) {
	sort.Strings(hashes)
}
