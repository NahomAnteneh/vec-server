package packfile

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBasicPackfileOperations(t *testing.T) {
	// Create a simple packfile directly using the basic structure
	tmpDir, err := os.MkdirTemp("", "packfile_basic_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packfilePath := filepath.Join(tmpDir, "basic.pack")

	// Create test data
	obj1Data := []byte("test blob content")
	obj1Hash := "0123456789abcdef0123456789abcdef01234567"

	// Create and write to packfile directly
	file, err := os.Create(packfilePath)
	if err != nil {
		t.Fatalf("Failed to create packfile: %v", err)
	}

	// Write header
	header := PackFileHeader{
		Signature:  [4]byte{'P', 'A', 'C', 'K'},
		Version:    2,
		NumObjects: 1,
	}

	if err := binary.Write(file, binary.BigEndian, &header); err != nil {
		file.Close()
		t.Fatalf("Failed to write packfile header: %v", err)
	}

	// Write object (one blob)
	// Write object header (type and size)
	// Type 3 (blob) in the high bits, size in the variable-length encoding
	firstByte := byte((uint8(OBJ_BLOB) << 4) & 0x70) // Type in bits 4-6
	firstByte |= byte(len(obj1Data) & 0x0F)          // Size in low 4 bits

	// If size doesn't fit in 4 bits, set continuation bit
	if len(obj1Data) >= 0x10 {
		firstByte |= 0x80
	}

	// Write first byte
	if _, err := file.Write([]byte{firstByte}); err != nil {
		file.Close()
		t.Fatalf("Failed to write object header: %v", err)
	}

	// Write additional size bytes if needed
	remainingSize := len(obj1Data) >> 4
	for remainingSize > 0 {
		nextByte := byte(remainingSize & 0x7F)
		remainingSize >>= 7
		if remainingSize > 0 {
			nextByte |= 0x80
		}
		if _, err := file.Write([]byte{nextByte}); err != nil {
			file.Close()
			t.Fatalf("Failed to write object size: %v", err)
		}
	}

	// Compress and write the object data
	compressedWriter := zlib.NewWriter(file)
	if _, err := compressedWriter.Write(obj1Data); err != nil {
		compressedWriter.Close()
		file.Close()
		t.Fatalf("Failed to write compressed data: %v", err)
	}
	if err := compressedWriter.Close(); err != nil {
		file.Close()
		t.Fatalf("Failed to close compressed writer: %v", err)
	}

	// Write a simple packfile checksum (zeros are fine for testing)
	checksum := make([]byte, 32) // SHA-256 is 32 bytes
	if _, err := file.Write(checksum); err != nil {
		file.Close()
		t.Fatalf("Failed to write packfile checksum: %v", err)
	}

	file.Close()

	// Create a simple index file
	indexPath := packfilePath + ".idx"
	idxFile, err := os.Create(indexPath)
	if err != nil {
		t.Fatalf("Failed to create index file: %v", err)
	}

	// Write index header (signature + version)
	if _, err := idxFile.Write([]byte{0xff, 't', 'O', 'c'}); err != nil { // Signature
		idxFile.Close()
		t.Fatalf("Failed to write index signature: %v", err)
	}
	if err := binary.Write(idxFile, binary.BigEndian, uint32(2)); err != nil { // Version
		idxFile.Close()
		t.Fatalf("Failed to write index version: %v", err)
	}

	// Write fanout table (256 entries of uint32)
	fanout := make([]uint32, 256)
	// Set the count for all entries after the first byte of the object hash
	firstByte = obj1Hash[0]
	firstByteVal := 0
	if firstByte >= '0' && firstByte <= '9' {
		firstByteVal = int(firstByte - '0')
	} else if firstByte >= 'a' && firstByte <= 'f' {
		firstByteVal = int(firstByte - 'a' + 10)
	}

	for i := firstByteVal; i < 256; i++ {
		fanout[i] = 1 // We have 1 object
	}

	for i := 0; i < 256; i++ {
		if err := binary.Write(idxFile, binary.BigEndian, fanout[i]); err != nil {
			idxFile.Close()
			t.Fatalf("Failed to write fanout table: %v", err)
		}
	}

	// Write object SHA (simplified)
	fakeObjSHA := make([]byte, 32) // 32 bytes for SHA-256
	copy(fakeObjSHA, []byte(obj1Hash))
	if _, err := idxFile.Write(fakeObjSHA); err != nil {
		idxFile.Close()
		t.Fatalf("Failed to write object hash: %v", err)
	}

	// Write CRC32 value (0 for testing)
	if err := binary.Write(idxFile, binary.BigEndian, uint32(0)); err != nil {
		idxFile.Close()
		t.Fatalf("Failed to write CRC32: %v", err)
	}

	// Write offset value (12 = size of packfile header)
	if err := binary.Write(idxFile, binary.BigEndian, uint32(12)); err != nil {
		idxFile.Close()
		t.Fatalf("Failed to write offset: %v", err)
	}

	// Write pack checksum and index checksum
	if _, err := idxFile.Write(make([]byte, 64)); err != nil { // 2 * 32 bytes
		idxFile.Close()
		t.Fatalf("Failed to write checksums: %v", err)
	}

	idxFile.Close()

	// Now try to parse the packfile
	fmt.Println("Attempting to parse packfile...")
	parsedObjects, err := ParseModernPackfile(packfilePath, true)
	if err != nil {
		t.Fatalf("Failed to parse packfile: %v", err)
	}

	// Check results
	if len(parsedObjects) != 1 {
		t.Errorf("Expected 1 object, got %d", len(parsedObjects))
	}

	if len(parsedObjects) > 0 {
		obj := parsedObjects[0]
		if obj.Type != OBJ_BLOB {
			t.Errorf("Expected object type OBJ_BLOB (%d), got %d", OBJ_BLOB, obj.Type)
		}

		if !bytes.Equal(obj.Data, obj1Data) {
			t.Errorf("Object data mismatch. Expected %q, got %q", obj1Data, obj.Data)
		}
	}
}

// TestPackfileCreateAndParse creates a packfile using CreateModernPackfile and then parses it
func TestPackfileCreateAndParse(t *testing.T) {
	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "packfile_create_parse_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packfilePath := filepath.Join(tmpDir, "test.pack")

	// Create a simple object to package
	objects := []Object{
		{
			Hash: "0123456789abcdef0123456789abcdef01234567", // 40 char SHA-1 hash
			Type: OBJ_BLOB,
			Data: []byte("Simple test content for packfile"),
		},
	}

	// Create the packfile
	err = CreateModernPackfile(objects, packfilePath)
	if err != nil {
		t.Fatalf("Failed to create packfile: %v", err)
	}

	// Verify packfile and index were created
	if _, err := os.Stat(packfilePath); os.IsNotExist(err) {
		t.Fatalf("Packfile was not created")
	}
	if _, err := os.Stat(packfilePath + ".idx"); os.IsNotExist(err) {
		t.Fatalf("Index file was not created")
	}

	// Parse the packfile
	parsedObjects, err := ParseModernPackfile(packfilePath, true)
	if err != nil {
		t.Fatalf("Failed to parse packfile: %v", err)
	}

	// Verify the parsed object
	if len(parsedObjects) != 1 {
		t.Fatalf("Expected 1 object, got %d", len(parsedObjects))
	}

	obj := parsedObjects[0]
	if obj.Type != OBJ_BLOB {
		t.Errorf("Expected object type OBJ_BLOB (%d), got %d", OBJ_BLOB, obj.Type)
	}

	if !bytes.Equal(obj.Data, objects[0].Data) {
		t.Errorf("Object data mismatch.\nExpected: %q\nGot: %q", objects[0].Data, obj.Data)
	}
}

// TestHashConversion tests conversion between different hash formats
func TestHashConversion(t *testing.T) {
	// Test SHA-1 hash (40 chars)
	sha1Hash := "0123456789abcdef0123456789abcdef01234567"
	sha1Bytes, err := hex.DecodeString(sha1Hash)
	if err != nil {
		t.Fatalf("Failed to decode SHA-1 hash: %v", err)
	}

	if len(sha1Bytes) != 20 {
		t.Errorf("Expected SHA-1 bytes to be 20 bytes, got %d bytes", len(sha1Bytes))
	}

	// Test padding SHA-1 to SHA-256 length
	var paddedSha1 [hashLength]byte
	copy(paddedSha1[:], sha1Bytes)

	// Verify padding worked correctly
	for i := 20; i < hashLength; i++ {
		if paddedSha1[i] != 0 {
			t.Errorf("Expected padding byte at position %d to be 0, got %d", i, paddedSha1[i])
		}
	}

	// Test SHA-256 hash (64 chars)
	sha256TestContent := []byte("test content for SHA-256")
	h := sha256.New()
	h.Write(sha256TestContent)
	sha256Bytes := h.Sum(nil)
	sha256Hex := hex.EncodeToString(sha256Bytes)

	if len(sha256Hex) != 64 {
		t.Errorf("Expected SHA-256 hex to be 64 chars, got %d chars", len(sha256Hex))
	}

	if len(sha256Bytes) != 32 {
		t.Errorf("Expected SHA-256 bytes to be 32 bytes, got %d bytes", len(sha256Bytes))
	}

	// Test conversion using hexToBytes
	hexToBytes, err := hexToBytes(sha256Hex)
	if err != nil {
		t.Fatalf("Failed to convert hex to bytes: %v", err)
	}

	if !bytes.Equal(hexToBytes[:], sha256Bytes) {
		t.Errorf("hexToBytes conversion failed")
	}
}

// TestSHA256PackfileCreationAndParsing tests creating and parsing packfiles with SHA-256 hashes
func TestSHA256PackfileCreationAndParsing(t *testing.T) {
	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "packfile_sha256_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packfilePath := filepath.Join(tmpDir, "sha256.pack")

	// Create test objects with SHA-256 hashes
	blobContent := []byte("blob content for SHA-256 test")
	h := sha256.New()
	header := fmt.Sprintf("blob %d\x00", len(blobContent))
	h.Write([]byte(header))
	h.Write(blobContent)
	sha256Hash := hex.EncodeToString(h.Sum(nil))

	// Verify hash length
	if len(sha256Hash) != 64 {
		t.Errorf("Expected SHA-256 hash to be 64 chars, got %d chars", len(sha256Hash))
	}

	// Create HashBytes
	hashBytes, err := hex.DecodeString(sha256Hash)
	if err != nil {
		t.Fatalf("Failed to decode SHA-256 hash: %v", err)
	}

	var hashBytesArray [hashLength]byte
	copy(hashBytesArray[:], hashBytes)

	// Create object with SHA-256 hash
	objects := []Object{
		{
			Hash:      sha256Hash,
			HashBytes: hashBytesArray,
			Type:      OBJ_BLOB,
			Data:      blobContent,
			Size:      uint64(len(blobContent)),
		},
	}

	// Create packfile
	err = CreateModernPackfile(objects, packfilePath)
	if err != nil {
		t.Fatalf("Failed to create packfile with SHA-256 hash: %v", err)
	}

	// Parse packfile
	parsedObjects, err := ParseModernPackfile(packfilePath, true)
	if err != nil {
		t.Fatalf("Failed to parse packfile with SHA-256 hash: %v", err)
	}

	// Verify parsed object
	if len(parsedObjects) != 1 {
		t.Fatalf("Expected 1 object, got %d", len(parsedObjects))
	}

	parsedObj := parsedObjects[0]

	// Verify hash is preserved correctly
	calculatedHash := calculateObjectHash(parsedObj.Type, parsedObj.Data)
	if calculatedHash != sha256Hash {
		t.Errorf("Hash mismatch. Expected %s, got %s", sha256Hash, calculatedHash)
	}

	// Verify HashBytes field was populated correctly
	expectedHashBytes, _ := hex.DecodeString(sha256Hash)
	if !bytes.Equal(parsedObj.HashBytes[:], expectedHashBytes) {
		t.Errorf("HashBytes field was not populated correctly")
	}

	// Verify content was preserved
	if !bytes.Equal(parsedObj.Data, blobContent) {
		t.Errorf("Content mismatch. Expected %q, got %q", blobContent, parsedObj.Data)
	}
}

// TestMixedHashFormatPackfile tests a packfile with both SHA-1 and SHA-256 hashes
func TestMixedHashFormatPackfile(t *testing.T) {
	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "packfile_mixed_hash_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packfilePath := filepath.Join(tmpDir, "mixed_hash.pack")

	// Create SHA-1 object
	sha1Content := []byte("content for SHA-1 object")
	sha1Hash := "abcdef0123456789abcdef0123456789abcdef01"
	var sha1HashBytes [hashLength]byte
	sha1Decoded, _ := hex.DecodeString(sha1Hash)
	copy(sha1HashBytes[:], sha1Decoded)

	// Create SHA-256 object
	sha256Content := []byte("content for SHA-256 object")
	h := sha256.New()
	header := fmt.Sprintf("blob %d\x00", len(sha256Content))
	h.Write([]byte(header))
	h.Write(sha256Content)
	sha256Hash := hex.EncodeToString(h.Sum(nil))
	var sha256HashBytes [hashLength]byte
	sha256Decoded, _ := hex.DecodeString(sha256Hash)
	copy(sha256HashBytes[:], sha256Decoded)

	// Create objects with different hash formats
	objects := []Object{
		{
			Hash:      sha1Hash,
			HashBytes: sha1HashBytes,
			Type:      OBJ_BLOB,
			Data:      sha1Content,
			Size:      uint64(len(sha1Content)),
		},
		{
			Hash:      sha256Hash,
			HashBytes: sha256HashBytes,
			Type:      OBJ_BLOB,
			Data:      sha256Content,
			Size:      uint64(len(sha256Content)),
		},
	}

	// Create packfile with mixed hash formats
	err = CreateModernPackfile(objects, packfilePath)
	if err != nil {
		t.Fatalf("Failed to create packfile with mixed hash formats: %v", err)
	}

	// Parse packfile
	parsedObjects, err := ParseModernPackfile(packfilePath, true)
	if err != nil {
		t.Fatalf("Failed to parse packfile with mixed hash formats: %v", err)
	}

	// Verify parsed objects
	if len(parsedObjects) != 2 {
		t.Fatalf("Expected 2 objects, got %d", len(parsedObjects))
	}

	// Create maps for easier lookup
	parsedObjMap := make(map[string]Object)
	for _, obj := range parsedObjects {
		parsedObjMap[obj.Hash] = obj
	}

	// Verify SHA-1 object
	sha1Obj, exists := parsedObjMap[sha1Hash]
	if !exists {
		t.Fatalf("SHA-1 object not found in parsed objects")
	}
	if !bytes.Equal(sha1Obj.Data, sha1Content) {
		t.Errorf("SHA-1 object content mismatch")
	}

	// Verify SHA-256 object
	sha256Obj, exists := parsedObjMap[sha256Hash]
	if !exists {
		// Try looking for recalculated hash
		recalculatedHash := calculateObjectHash(OBJ_BLOB, sha256Content)
		sha256Obj, exists = parsedObjMap[recalculatedHash]
		if !exists {
			t.Fatalf("SHA-256 object not found in parsed objects")
		}
	}
	if !bytes.Equal(sha256Obj.Data, sha256Content) {
		t.Errorf("SHA-256 object content mismatch")
	}
}

// TestPackfileDeltaWithDifferentHashFormats tests delta compression between objects with different hash formats
func TestPackfileDeltaWithDifferentHashFormats(t *testing.T) {
	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "packfile_delta_hash_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packfilePath := filepath.Join(tmpDir, "delta_hash.pack")

	// Base content
	baseContent := []byte("This is the base content that will be modified slightly")

	// SHA-1 base object
	sha1Hash := "abcdef0123456789abcdef0123456789abcdef01"
	var sha1HashBytes [hashLength]byte
	sha1Decoded, _ := hex.DecodeString(sha1Hash)
	copy(sha1HashBytes[:], sha1Decoded)

	// SHA-256 delta object with similar content
	deltaContent := []byte("This is the base content that will be modified significantly")
	h := sha256.New()
	header := fmt.Sprintf("blob %d\x00", len(deltaContent))
	h.Write([]byte(header))
	h.Write(deltaContent)
	sha256Hash := hex.EncodeToString(h.Sum(nil))
	var sha256HashBytes [hashLength]byte
	sha256Decoded, _ := hex.DecodeString(sha256Hash)
	copy(sha256HashBytes[:], sha256Decoded)

	// Create delta between them
	deltaData, err := testCreateDelta(baseContent, deltaContent)
	if err != nil {
		t.Fatalf("Failed to create delta: %v", err)
	}

	// Create objects
	objects := []Object{
		// Base object with SHA-1 hash
		{
			Hash:      sha1Hash,
			HashBytes: sha1HashBytes,
			Type:      OBJ_BLOB,
			Data:      baseContent,
			Size:      uint64(len(baseContent)),
		},
		// Delta object with SHA-256 hash referencing SHA-1 base
		{
			Hash:          sha256Hash,
			HashBytes:     sha256HashBytes,
			Type:          OBJ_REF_DELTA,
			Data:          deltaData,
			Size:          uint64(len(deltaData)),
			BaseHash:      sha1Hash,
			BaseHashBytes: sha1HashBytes,
		},
	}

	// Create packfile with delta references between different hash formats
	err = CreateModernPackfile(objects, packfilePath)
	if err != nil {
		t.Fatalf("Failed to create delta packfile with different hash formats: %v", err)
	}

	// Parse packfile
	parsedObjects, err := ParseModernPackfile(packfilePath, true)
	if err != nil {
		t.Fatalf("Failed to parse delta packfile: %v", err)
	}

	// Verify we have both objects
	if len(parsedObjects) != 2 {
		t.Fatalf("Expected 2 objects, got %d", len(parsedObjects))
	}

	// Create maps for easier lookup
	parsedObjMap := make(map[string]Object)
	for _, obj := range parsedObjects {
		parsedObjMap[obj.Hash] = obj
	}

	// Verify objects were properly resolved
	sha1Obj, exists := parsedObjMap[sha1Hash]
	if !exists {
		t.Fatalf("Base object with SHA-1 hash not found")
	}
	if !bytes.Equal(sha1Obj.Data, baseContent) {
		t.Errorf("Base object content mismatch")
	}

	// Try different ways to find the delta object since hash might be recalculated
	var deltaObj Object
	deltaObj, exists = parsedObjMap[sha256Hash]
	if !exists {
		// Try with recalculated hash
		recalculatedHash := calculateObjectHash(OBJ_BLOB, deltaContent)
		deltaObj, exists = parsedObjMap[recalculatedHash]
		if !exists {
			// Last resort - look for object with matching content
			for _, obj := range parsedObjects {
				if bytes.Equal(obj.Data, deltaContent) {
					deltaObj = obj
					exists = true
					break
				}
			}
			if !exists {
				t.Fatalf("Delta object not found in parsed objects")
			}
		}
	}

	if !bytes.Equal(deltaObj.Data, deltaContent) {
		t.Errorf("Delta object content mismatch.\nExpected: %q\nGot: %q",
			string(deltaContent), string(deltaObj.Data))
	}
}

// testCreateDelta creates a simple delta between base and target content for testing
func testCreateDelta(baseContent, targetContent []byte) ([]byte, error) {
	// For test purposes, we'll use a very simple delta format:
	// 1. First byte: command type (0=copy from base, 1=insert new)
	// 2. Next 4 bytes: uint32 length of data to copy or insert
	// 3. If insert command, the actual bytes to insert

	// Create a buffer for the delta
	var delta bytes.Buffer

	// Find the longest common prefix
	prefixLen := 0
	for prefixLen < len(baseContent) && prefixLen < len(targetContent) {
		if baseContent[prefixLen] != targetContent[prefixLen] {
			break
		}
		prefixLen++
	}

	// If there's a common prefix, add a command to copy it
	if prefixLen > 0 {
		// Write copy command (0)
		delta.WriteByte(0)

		// Write length (4 bytes, big endian)
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(prefixLen))
		delta.Write(lengthBytes)
	}

	// Add insert command for the rest of the target content
	if prefixLen < len(targetContent) {
		// Write insert command (1)
		delta.WriteByte(1)

		// Write length of data to insert
		insertLen := len(targetContent) - prefixLen
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(insertLen))
		delta.Write(lengthBytes)

		// Write the actual data to insert
		delta.Write(targetContent[prefixLen:])
	}

	return delta.Bytes(), nil
}

// testApplyDelta applies our simple test delta format to base content
func testApplyDelta(baseContent, deltaData []byte) ([]byte, error) {
	if len(deltaData) == 0 {
		return nil, fmt.Errorf("empty delta data")
	}

	var result bytes.Buffer
	deltaPos := 0

	for deltaPos < len(deltaData) {
		// Read command type
		cmdType := deltaData[deltaPos]
		deltaPos++

		// Read length (4 bytes)
		if deltaPos+4 > len(deltaData) {
			return nil, fmt.Errorf("delta data truncated")
		}
		length := binary.BigEndian.Uint32(deltaData[deltaPos : deltaPos+4])
		deltaPos += 4

		if cmdType == 0 {
			// Copy command - copy from base
			if uint32(len(baseContent)) < length {
				return nil, fmt.Errorf("delta wants to copy %d bytes, but base is only %d bytes",
					length, len(baseContent))
			}
			result.Write(baseContent[:length])
		} else if cmdType == 1 {
			// Insert command - copy from delta
			if deltaPos+int(length) > len(deltaData) {
				return nil, fmt.Errorf("delta wants to insert %d bytes, but only %d bytes available",
					length, len(deltaData)-deltaPos)
			}
			result.Write(deltaData[deltaPos : deltaPos+int(length)])
			deltaPos += int(length)
		} else {
			return nil, fmt.Errorf("unknown delta command type: %d", cmdType)
		}
	}

	return result.Bytes(), nil
}
