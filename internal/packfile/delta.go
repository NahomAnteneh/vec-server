package packfile

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// Match represents a match between a base and target sequence during delta computation.
// It stores the offset in the base sequence and the length of the match.
type Match struct {
	BaseOffset  int
	MatchLength int
}

// applyDelta applies a delta to a base object to produce a new object
func applyDelta(base, delta []byte) ([]byte, error) {
	if len(delta) < 2 {
		return nil, errors.New("delta too short")
	}

	// Read the source and target size from the delta
	sourceSize, bytesRead := decodeSize(delta)
	delta = delta[bytesRead:]

	targetSize, bytesRead := decodeSize(delta)
	delta = delta[bytesRead:]

	// Verify the source size matches our base object
	if sourceSize != uint64(len(base)) {
		return nil, fmt.Errorf("source size mismatch: expected %d, got %d", len(base), sourceSize)
	}

	// Create a buffer for the target object
	result := make([]byte, 0, targetSize)

	// Apply delta instructions
	for len(delta) > 0 {
		// Read the instruction byte
		cmd := delta[0]
		delta = delta[1:]

		if cmd == 0 {
			// Reserved, should not appear in valid delta
			return nil, errors.New("invalid delta: zero command byte")
		} else if cmd&0x80 != 0 {
			// Copy instruction
			var offset, size uint32
			offsetBytes := 0
			sizeBytes := 0

			// Read offset (if present)
			if cmd&0x01 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset = uint32(delta[0])
				offsetBytes = 1
				delta = delta[1:]
			}
			if cmd&0x02 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 8
				offsetBytes++
				delta = delta[1:]
			}
			if cmd&0x04 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 16
				offsetBytes++
				delta = delta[1:]
			}
			if cmd&0x08 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 24
				offsetBytes++
				delta = delta[1:]
			}

			// Read size (if present)
			if cmd&0x10 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size = uint32(delta[0])
				sizeBytes = 1
				delta = delta[1:]
			}
			if cmd&0x20 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size |= uint32(delta[0]) << 8
				sizeBytes++
				delta = delta[1:]
			}
			if cmd&0x40 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size |= uint32(delta[0]) << 16
				sizeBytes++
				delta = delta[1:]
			}

			// If no size specified, use default
			if sizeBytes == 0 {
				size = 0x10000 // 64KB
			}

			// Validate the copy operation
			if offset+size > uint32(len(base)) {
				return nil, fmt.Errorf("invalid copy: offset %d + size %d > base length %d",
					offset, size, len(base))
			}

			// Copy from base
			result = append(result, base[offset:offset+size]...)
		} else {
			// Insert instruction
			size := int(cmd) // cmd is the size for insert
			if len(delta) < size {
				return nil, errors.New("delta too short for insert data")
			}

			// Insert literal data
			result = append(result, delta[:size]...)
			delta = delta[size:]
		}
	}

	// Verify the result size matches the expected target size
	if uint64(len(result)) != targetSize {
		return nil, fmt.Errorf("target size mismatch: expected %d, got %d",
			targetSize, len(result))
	}

	return result, nil
}

// decodeSize decodes a size value from a delta and returns the size and bytes read
func decodeSize(delta []byte) (uint64, int) {
	var size uint64
	shift := uint(0)
	bytesRead := 0

	for {
		if bytesRead >= len(delta) {
			// Unexpected end of input, return what we have
			return size, bytesRead
		}

		b := delta[bytesRead]
		bytesRead++

		size |= uint64(b&0x7F) << shift
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}

	return size, bytesRead
}

// createDelta creates a delta from a base object to a target object
// using an improved algorithm for finding optimal copy instructions
func createDelta(base, target []byte) ([]byte, error) {
	// Create buffer to hold the delta
	var buffer bytes.Buffer

	// Encode base size
	encodeSize(&buffer, uint64(len(base)))

	// Encode target size
	encodeSize(&buffer, uint64(len(target)))

	// Early return if target is empty
	if len(target) == 0 {
		return buffer.Bytes(), nil
	}

	// Early return if base is empty - just use insert for everything
	if len(base) == 0 {
		// Insert the entire target
		pos := 0
		for pos < len(target) {
			// Insert in chunks of MAX_INSERT_SIZE
			chunkSize := len(target) - pos
			if chunkSize > 127 {
				chunkSize = 127
			}
			buffer.WriteByte(byte(chunkSize))
			buffer.Write(target[pos : pos+chunkSize])
			pos += chunkSize
		}
		return buffer.Bytes(), nil
	}

	// Create indices for efficient substring matching
	matchCache := buildMatchCache(base, target)

	// Compute delta operations using match cache
	err := computeDeltaWithCache(&buffer, base, target, matchCache)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// encodeSize encodes a size value for a delta
func encodeSize(buffer *bytes.Buffer, size uint64) {
	for {
		b := byte(size & 0x7F)
		size >>= 7
		if size == 0 {
			buffer.WriteByte(b)
			break
		}
		buffer.WriteByte(b | 0x80)
	}
}

// computeDelta computes the delta operations between base and target
// using a sliding window approach for optimal instruction selection
func computeDelta(buffer *bytes.Buffer, base, target []byte) error {
	// Early return if target is empty
	if len(target) == 0 {
		return nil
	}

	// Minimum match size worth encoding as a copy
	const MIN_COPY_SIZE = 4

	// Maximum size for a single insert instruction
	const MAX_INSERT_SIZE = 127

	// Current position in target
	pos := 0

	// Buffer for collecting insert data
	insertBuf := make([]byte, 0, MAX_INSERT_SIZE)

	// Flush any pending insert data
	flushInsert := func() {
		if len(insertBuf) > 0 {
			encodeInsertCommand(buffer, insertBuf)
			insertBuf = insertBuf[:0]
		}
	}

	// Process the target until we've consumed it all
	for pos < len(target) {
		// Look for matches at current position
		matchOffset, matchLength := findLongestMatch(base, target[pos:])

		// If we found a match that's worth encoding as a copy
		if matchLength >= MIN_COPY_SIZE {
			// Flush any pending insert data
			flushInsert()

			// Encode the copy instruction
			encodeCopyCommand(buffer, matchOffset, matchLength)

			// Advance position
			pos += int(matchLength)
		} else {
			// Add current byte to insert buffer
			insertBuf = append(insertBuf, target[pos])
			pos++

			// If insert buffer is full, flush it
			if len(insertBuf) >= MAX_INSERT_SIZE {
				flushInsert()
			}
		}
	}

	// Flush any remaining insert data
	flushInsert()

	return nil
}

// findLongestMatch finds the longest matching substring in base for the start of target
// using a rolling hash algorithm (Rabin-Karp) for efficient matching
func findLongestMatch(base, target []byte) (offset, length uint32) {
	if len(target) < 4 {
		return 0, 0 // Need at least 4 bytes for meaningful matching
	}

	const (
		prime        = 16777619  // FNV prime
		windowSize   = 4         // Initial window size for hash comparison
		maxMatchSize = 64 * 1024 // Max match size (64KB)
	)

	// Create a hash map for the base content
	baseHashes := make(map[uint32][]uint32)

	// Helper function to compute hash of a small window
	computeHash := func(data []byte, start, end int) uint32 {
		h := uint32(2166136261) // FNV offset basis
		for i := start; i < end && i < len(data); i++ {
			h = (h ^ uint32(data[i])) * prime
		}
		return h
	}

	// Compute hashes for all windowSize-byte segments in base
	for i := 0; i <= len(base)-windowSize; i++ {
		h := computeHash(base, i, i+windowSize)
		baseHashes[h] = append(baseHashes[h], uint32(i))
	}

	// Compute hash of the first windowSize bytes of target
	targetHash := computeHash(target, 0, windowSize)

	// Track best match
	bestLength := uint32(0)
	bestOffset := uint32(0)

	// Check candidate matches using hash
	if candidates, ok := baseHashes[targetHash]; ok {
		for _, pos := range candidates {
			// Verify and extend match
			matchLen := uint32(0)
			maxLen := uint32(min(len(base)-int(pos), len(target)))
			if maxLen > maxMatchSize {
				maxLen = maxMatchSize
			}

			for matchLen < maxLen && base[pos+matchLen] == target[matchLen] {
				matchLen++
			}

			if matchLen > bestLength {
				bestLength = matchLen
				bestOffset = pos
			}
		}
	}

	// If we didn't find a good match with the initial window, try with longer windows
	if bestLength < 12 && len(target) >= 8 {
		// Try with 8-byte window for larger matches
		largeWindowSize := 8

		largeBaseHashes := make(map[uint64][]uint32)

		// Compute 64-bit hashes for larger segments
		computeLargeHash := func(data []byte, start, end int) uint64 {
			h := uint64(14695981039346656037) // FNV-1a 64-bit offset
			for i := start; i < end && i < len(data); i++ {
				h = (h ^ uint64(data[i])) * 1099511628211 // FNV-1a 64-bit prime
			}
			return h
		}

		// Compute hashes for largeWindowSize-byte segments
		for i := 0; i <= len(base)-largeWindowSize; i++ {
			h := computeLargeHash(base, i, i+largeWindowSize)
			largeBaseHashes[h] = append(largeBaseHashes[h], uint32(i))
		}

		targetLargeHash := computeLargeHash(target, 0, largeWindowSize)

		if candidates, ok := largeBaseHashes[targetLargeHash]; ok {
			for _, pos := range candidates {
				matchLen := uint32(0)
				maxLen := uint32(min(len(base)-int(pos), len(target)))
				if maxLen > maxMatchSize {
					maxLen = maxMatchSize
				}

				for matchLen < maxLen && base[pos+matchLen] == target[matchLen] {
					matchLen++
				}

				if matchLen > bestLength {
					bestLength = matchLen
					bestOffset = pos
				}
			}
		}
	}

	return bestOffset, bestLength
}

// encodeCopyCommand encodes a copy command in the delta format
func encodeCopyCommand(buffer *bytes.Buffer, offset, length uint32) {
	// Copy command: 1000xxxx [offset] [size]
	// Where bits xxxx indicate which offset/size bytes are present

	var cmd byte = 0x80 // Copy command (bit 7 set)
	var offsetBytes, sizeBytes [4]byte
	numOffsetBytes := 0
	numSizeBytes := 0

	// Encode offset bytes (little-endian)
	if offset != 0 {
		if offset&0xFF != 0 {
			cmd |= 0x01
			offsetBytes[numOffsetBytes] = byte(offset)
			numOffsetBytes++
		}
		offset >>= 8

		if offset&0xFF != 0 {
			cmd |= 0x02
			offsetBytes[numOffsetBytes] = byte(offset)
			numOffsetBytes++
		}
		offset >>= 8

		if offset&0xFF != 0 {
			cmd |= 0x04
			offsetBytes[numOffsetBytes] = byte(offset)
			numOffsetBytes++
		}
		offset >>= 8

		if offset&0xFF != 0 {
			cmd |= 0x08
			offsetBytes[numOffsetBytes] = byte(offset)
			numOffsetBytes++
		}
	}

	// Encode size bytes (little-endian)
	if length != 0x10000 { // If not the default size
		if length&0xFF != 0 {
			cmd |= 0x10
			sizeBytes[numSizeBytes] = byte(length)
			numSizeBytes++
		}
		length >>= 8

		if length&0xFF != 0 {
			cmd |= 0x20
			sizeBytes[numSizeBytes] = byte(length)
			numSizeBytes++
		}
		length >>= 8

		if length&0xFF != 0 {
			cmd |= 0x40
			sizeBytes[numSizeBytes] = byte(length)
			numSizeBytes++
		}
	}

	// Write the command byte
	buffer.WriteByte(cmd)

	// Write offset bytes
	for i := 0; i < numOffsetBytes; i++ {
		buffer.WriteByte(offsetBytes[i])
	}

	// Write size bytes
	for i := 0; i < numSizeBytes; i++ {
		buffer.WriteByte(sizeBytes[i])
	}
}

// encodeInsertCommand encodes an insert command in the delta format
// handling large inserts by breaking them into chunks
func encodeInsertCommand(buffer *bytes.Buffer, data []byte) {
	const maxChunkSize = 127 // Maximum size per insert command

	remaining := len(data)
	offset := 0

	for remaining > 0 {
		// Determine size for this chunk
		size := remaining
		if size > maxChunkSize {
			size = maxChunkSize
		}

		// Write insert command (size byte)
		// For insert commands, the MSB (0x80) is not set
		buffer.WriteByte(byte(size))

		// Write the actual data for this chunk
		buffer.Write(data[offset : offset+size])

		// Update position and remaining count
		offset += size
		remaining -= size
	}
}

// OptimizeObjects creates delta objects to reduce storage/transfer size
func OptimizeObjects(objects []Object) ([]Object, error) {
	if len(objects) <= 1 {
		return objects, nil // No optimization possible with 0 or 1 objects
	}

	// Calculate similarities between objects
	similarities := calculateSimilarities(objects)

	// Sort by highest similarity score
	sortSimilarities(similarities)

	// Build delta chains
	chains := buildDeltaChains(similarities, objects)

	// Create result list starting with base objects
	result := make([]Object, 0, len(objects))
	deltas := make([]Object, 0)
	processedHashes := make(map[string]bool)

	// First add all base objects (objects that aren't deltas)
	for _, chain := range chains {
		// Find the base object
		baseObj := findObjectByHash(objects, chain.BaseHash)
		if baseObj == nil {
			// This shouldn't happen if buildDeltaChains worked correctly
			return nil, fmt.Errorf("base object not found: %s", chain.BaseHash)
		}

		// Only add base objects once
		if !processedHashes[baseObj.Hash] {
			result = append(result, *baseObj)
			processedHashes[baseObj.Hash] = true
		}

		// Process deltas in this chain
		for _, deltaDes := range chain.Deltas {
			targetObj := findObjectByHash(objects, deltaDes.TargetHash)
			if targetObj == nil {
				return nil, fmt.Errorf("target object not found: %s", deltaDes.TargetHash)
			}

			// Create delta between base and target
			deltaData, err := createDelta(baseObj.Data, targetObj.Data)
			if err != nil {
				// Skip this delta if it fails, but log a warning and keep the original object
				fmt.Printf("Warning: Failed to create delta for %s -> %s: %v\n",
					baseObj.Hash, targetObj.Hash, err)

				// Add the original object instead
				if !processedHashes[targetObj.Hash] {
					result = append(result, *targetObj)
					processedHashes[targetObj.Hash] = true
				}
				continue
			}

			// Check if the delta is actually smaller - if not, use original
			if len(deltaData) >= len(targetObj.Data) {
				// Delta is not smaller, use original object
				if !processedHashes[targetObj.Hash] {
					result = append(result, *targetObj)
					processedHashes[targetObj.Hash] = true
				}
				continue
			}

			// Create delta object
			deltaObj := Object{
				Hash:     targetObj.Hash,
				Type:     OBJ_REF_DELTA, // Use OBJ_REF_DELTA for packfile compatibility
				Data:     deltaData,
				BaseHash: baseObj.Hash, // Set the base hash
			}

			// Store for second pass
			deltas = append(deltas, deltaObj)
			processedHashes[targetObj.Hash] = true
		}
	}

	// Add any remaining objects that weren't included in delta chains
	for _, obj := range objects {
		if !processedHashes[obj.Hash] {
			result = append(result, obj)
			processedHashes[obj.Hash] = true
		}
	}

	// Add deltas at the end (after their bases)
	result = append(result, deltas...)

	return result, nil
}

// Constants for delta compression
const (
	// Minimum bytes to save to use a delta
	minDeltaSavings = 512

	// Maximum delta chain length
	maxChainDepth = 5

	// Chunking size for calculating similarity
	chunkSize = 64
)

// DeltaChain represents a chain of delta objects with a common base
type DeltaChain struct {
	BaseHash string
	Deltas   []DeltaDescriptor
}

// DeltaDescriptor describes a delta relationship
type DeltaDescriptor struct {
	TargetHash      string
	SimilarityScore float64
}

// ObjectSimilarity represents the similarity between two objects
type ObjectSimilarity struct {
	Obj1Hash string
	Obj2Hash string
	Score    float64
}

// findObjectByHash finds an object by its hash in a slice of objects
func findObjectByHash(objects []Object, hash string) *Object {
	for i := range objects {
		if objects[i].Hash == hash {
			return &objects[i]
		}
	}
	return nil
}

// calculateSimilarities calculates similarity scores between objects
func calculateSimilarities(objects []Object) []ObjectSimilarity {
	// For large repositories, limit the comparisons to reasonable numbers
	maxComparisons := 10000 // Arbitrary limit to prevent excessive calculations

	result := make([]ObjectSimilarity, 0)

	// Group objects by type for more relevant comparisons
	objectsByType := make(map[ObjectType][]Object)
	for _, obj := range objects {
		objectsByType[obj.Type] = append(objectsByType[obj.Type], obj)
	}

doneComparing: // Label for the outer loop structure
	// Process each type separately
	for _, typeObjects := range objectsByType {
		// Sort by size to prefer similar sized objects for deltas
		sort.Slice(typeObjects, func(i, j int) bool {
			return len(typeObjects[i].Data) < len(typeObjects[j].Data)
		})

		// Compare objects of the same type
		comparisons := 0
		for i := 0; i < len(typeObjects); i++ {
			// Limit number of comparisons per object based on type
			maxPerObject := 50
			if typeObjects[i].Type == OBJ_BLOB {
				// Blobs can have many more comparisons as they're more likely to be similar
				maxPerObject = 20
			}

			comparisonCount := 0
			for j := i + 1; j < len(typeObjects) && comparisonCount < maxPerObject; j++ {
				// Skip objects that are too different in size
				sizeRatio := float64(len(typeObjects[i].Data)) / float64(len(typeObjects[j].Data))
				if sizeRatio < 0.5 || sizeRatio > 2.0 {
					continue
				}

				score := calculateSimilarityScore(typeObjects[i].Data, typeObjects[j].Data)
				if score > 0.3 { // Only consider objects with some similarity
					result = append(result, ObjectSimilarity{
						Obj1Hash: typeObjects[i].Hash,
						Obj2Hash: typeObjects[j].Hash,
						Score:    score,
					})
				}

				comparisonCount++
				comparisons++
				if comparisons >= maxComparisons {
					// We've done enough comparisons overall
					break doneComparing // Break out of the labeled loop structure
				}
			}
		}
	}

	// If break doneComparing was hit, execution jumps here directly from the break
	return result
}

// calculateSimilarityScore calculates a similarity score between two byte arrays
// using a multi-level approach for more accurate results
// Higher score means more similar (0.0 to 1.0)
func calculateSimilarityScore(data1, data2 []byte) float64 {
	// Fast path: equal data
	if bytes.Equal(data1, data2) {
		return 1.0
	}

	// Quick check: if sizes are vastly different, similarity will be low
	// This check helps avoid unnecessary computation for obvious non-matches
	sizeRatio := float64(min(len(data1), len(data2))) / float64(max(len(data1), len(data2)))
	if sizeRatio < 0.3 {
		// Very different sizes mean low similarity
		return sizeRatio * 0.5 // Scale down further because size isn't everything
	}

	// For small objects, use direct Jaccard similarity on shingles
	if len(data1) < 4096 && len(data2) < 4096 {
		return calculateSmallObjectSimilarity(data1, data2)
	}

	// For larger objects, use multi-level fingerprinting
	return calculateLargeObjectSimilarity(data1, data2)
}

// calculateSmallObjectSimilarity calculates similarity for small objects
// using character-level Jaccard similarity with shingles
func calculateSmallObjectSimilarity(data1, data2 []byte) float64 {
	// Create shingles (n-grams) of the data
	const shingleSize = 4 // 4-gram shingles

	// Function to create shingles map
	createShingles := func(data []byte) map[string]struct{} {
		shingles := make(map[string]struct{})
		if len(data) < shingleSize {
			// For very small data, use the whole thing as one shingle
			shingles[string(data)] = struct{}{}
			return shingles
		}

		// Create overlapping shingles
		for i := 0; i <= len(data)-shingleSize; i++ {
			shingle := string(data[i : i+shingleSize])
			shingles[shingle] = struct{}{}
		}
		return shingles
	}

	// Get shingles for both objects
	shingles1 := createShingles(data1)
	shingles2 := createShingles(data2)

	// Count common shingles (intersection)
	commonCount := 0
	for shingle := range shingles1 {
		if _, exists := shingles2[shingle]; exists {
			commonCount++
		}
	}

	// Calculate Jaccard similarity: |A ∩ B| / |A ∪ B|
	totalShingles := len(shingles1) + len(shingles2) - commonCount
	if totalShingles == 0 {
		return 0.0 // Should not happen, but just in case
	}

	return float64(commonCount) / float64(totalShingles)
}

// calculateLargeObjectSimilarity calculates similarity for large objects
// using multi-level fingerprinting for efficiency
func calculateLargeObjectSimilarity(data1, data2 []byte) float64 {
	// Create fingerprints at multiple granularities
	smallFP1 := createFingerprintsAtSize(data1, 64) // Small chunks
	smallFP2 := createFingerprintsAtSize(data2, 64)

	mediumFP1 := createFingerprintsAtSize(data1, 256) // Medium chunks
	mediumFP2 := createFingerprintsAtSize(data2, 256)

	largeFP1 := createFingerprintsAtSize(data1, 1024) // Large chunks
	largeFP2 := createFingerprintsAtSize(data2, 1024)

	// Calculate similarity at each level
	smallSim := calculateFingerprintSimilarity(smallFP1, smallFP2)
	mediumSim := calculateFingerprintSimilarity(mediumFP1, mediumFP2)
	largeSim := calculateFingerprintSimilarity(largeFP1, largeFP2)

	// Weight the similarities - larger chunks get higher weight
	// because they represent more significant similarities
	return smallSim*0.2 + mediumSim*0.3 + largeSim*0.5
}

// createFingerprintsAtSize creates fingerprints from data at the specified chunk size
func createFingerprintsAtSize(data []byte, chunkSize int) map[uint64]struct{} {
	result := make(map[uint64]struct{})

	if len(data) < chunkSize {
		result[simpleHash(data)] = struct{}{}
		return result
	}

	// Sample the data at regular intervals
	numSamples := 100
	if len(data) < chunkSize*numSamples {
		// For smaller files, use overlapping chunks with step size
		step := max(1, chunkSize/4)
		for i := 0; i <= len(data)-chunkSize; i += step {
			chunk := data[i : i+chunkSize]
			result[simpleHash(chunk)] = struct{}{}
		}
	} else {
		// For large files, take evenly distributed samples
		step := (len(data) - chunkSize) / numSamples
		for i := 0; i < len(data)-chunkSize; i += step {
			chunk := data[i : i+chunkSize]
			result[simpleHash(chunk)] = struct{}{}
		}

		// Always include the beginning and end of the file
		// These are often significant for matching
		if len(data) >= chunkSize*2 {
			result[simpleHash(data[:chunkSize])] = struct{}{}
			result[simpleHash(data[len(data)-chunkSize:])] = struct{}{}
		}
	}

	return result
}

// calculateFingerprintSimilarity calculates the Jaccard similarity between two fingerprint sets
func calculateFingerprintSimilarity(fp1, fp2 map[uint64]struct{}) float64 {
	// Count the intersection
	commonCount := 0
	for h := range fp1 {
		if _, exists := fp2[h]; exists {
			commonCount++
		}
	}

	// Calculate Jaccard similarity
	totalCount := len(fp1) + len(fp2) - commonCount
	if totalCount == 0 {
		return 0.0
	}

	return float64(commonCount) / float64(totalCount)
}

// simpleHash creates a simple hash of a byte slice
func simpleHash(data []byte) uint64 {
	h := uint64(0)
	for i, b := range data {
		h = h*31 + uint64(b)
		if i > 1000 { // Limit computation for large chunks
			break
		}
	}
	return h
}

// sortSimilarities sorts object similarities by score (highest first)
func sortSimilarities(similarities []ObjectSimilarity) {
	sort.Slice(similarities, func(i, j int) bool {
		return similarities[i].Score > similarities[j].Score
	})
}

// buildDeltaChains builds optimal delta chains from similarity scores
// using an improved algorithm that minimizes overall delta size
func buildDeltaChains(similarities []ObjectSimilarity, objects []Object) []DeltaChain {
	// Create object size map for quick lookup
	objectSizes := make(map[string]int)
	objectTypes := make(map[string]ObjectType)
	for _, obj := range objects {
		objectSizes[obj.Hash] = len(obj.Data)
		objectTypes[obj.Hash] = obj.Type
	}

	// Maps to track object roles
	isBaseObject := make(map[string]bool)
	isDeltaObject := make(map[string]bool)

	// Map to store chains by base hash
	chains := make(map[string]*DeltaChain)

	// Create graph of potential delta relationships
	deltaGraph := make(map[string]map[string]float64)
	for _, sim := range similarities {
		if sim.Score < 0.1 {
			continue // Skip low-similarity pairs
		}

		// Initialize graph nodes if needed
		if deltaGraph[sim.Obj1Hash] == nil {
			deltaGraph[sim.Obj1Hash] = make(map[string]float64)
		}
		if deltaGraph[sim.Obj2Hash] == nil {
			deltaGraph[sim.Obj2Hash] = make(map[string]float64)
		}

		// Add edges in both directions (will decide direction later)
		deltaGraph[sim.Obj1Hash][sim.Obj2Hash] = sim.Score
		deltaGraph[sim.Obj2Hash][sim.Obj1Hash] = sim.Score
	}

	// Sort objects by type priority, then by size (smallest first)
	// We want commits and trees as base objects when possible
	allObjects := make([]string, 0, len(objectSizes))
	for hash := range objectSizes {
		allObjects = append(allObjects, hash)
	}

	// Sort by type priority and size
	sort.Slice(allObjects, func(i, j int) bool {
		hashI, hashJ := allObjects[i], allObjects[j]
		typeI, typeJ := objectTypes[hashI], objectTypes[hashJ]

		// Type priority: commit > tree > blob
		if typeI != typeJ {
			if typeI == OBJ_COMMIT {
				return true
			}
			if typeJ == OBJ_COMMIT {
				return false
			}
			if typeI == OBJ_TREE {
				return true
			}
			if typeJ == OBJ_TREE {
				return false
			}
		}

		// For same type, prefer smaller objects as base
		return objectSizes[hashI] < objectSizes[hashJ]
	})

	// Function to estimate delta size between two objects
	estimateDeltaSize := func(baseHash, targetHash string) int {
		// Similarity score is between 0 and 1, higher means more similar
		score := deltaGraph[baseHash][targetHash]

		// Rough estimation: delta size is inversely proportional to similarity
		// For perfect similarity (1.0), delta would be close to 0
		// For no similarity (0.0), delta would be close to target size
		estimatedSavings := int(float64(objectSizes[targetHash]) * score * 0.8)
		return objectSizes[targetHash] - estimatedSavings
	}

	// Greedy algorithm to build delta chains
	for _, candidateBase := range allObjects {
		// Skip if this object is already a delta
		if isDeltaObject[candidateBase] {
			continue
		}

		// Find all objects that could delta against this base
		potentialDeltas := make([]string, 0)
		for targetHash, score := range deltaGraph[candidateBase] {
			// Skip low scores or objects already used
			if score < 0.1 || isDeltaObject[targetHash] {
				continue
			}

			// Make sure using delta would actually save space
			deltaSize := estimateDeltaSize(candidateBase, targetHash)
			if deltaSize >= objectSizes[targetHash] {
				continue
			}

			potentialDeltas = append(potentialDeltas, targetHash)
		}

		// Sort potential deltas by space savings (highest first)
		sort.Slice(potentialDeltas, func(i, j int) bool {
			targetI, targetJ := potentialDeltas[i], potentialDeltas[j]
			savingsI := objectSizes[targetI] - estimateDeltaSize(candidateBase, targetI)
			savingsJ := objectSizes[targetJ] - estimateDeltaSize(candidateBase, targetJ)
			return savingsI > savingsJ
		})

		// If we found deltas worth making, create a chain
		if len(potentialDeltas) > 0 {
			chain := &DeltaChain{
				BaseHash: candidateBase,
				Deltas:   []DeltaDescriptor{},
			}

			isBaseObject[candidateBase] = true

			// Add deltas to chain
			for _, targetHash := range potentialDeltas {
				// Skip if already used
				if isDeltaObject[targetHash] {
					continue
				}

				score := deltaGraph[candidateBase][targetHash]
				chain.Deltas = append(chain.Deltas, DeltaDescriptor{
					TargetHash:      targetHash,
					SimilarityScore: score,
				})

				isDeltaObject[targetHash] = true
			}

			// Only store chains that have at least one delta
			if len(chain.Deltas) > 0 {
				chains[candidateBase] = chain
			}
		}
	}

	// Convert map to slice
	result := make([]DeltaChain, 0, len(chains))
	for _, chain := range chains {
		result = append(result, *chain)
	}

	return result
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// buildMatchCache builds a cache of potential matches between base and target
// for efficient delta computation
func buildMatchCache(base, target []byte) map[int][]Match {
	const (
		minMatchSize = 4 // Minimum match size worth considering
		hashWindow   = 4 // Size of window for initial hash matching
	)

	// Create map from position in target to potential matches in base
	matches := make(map[int][]Match)

	// Create hash table for quick lookup of base sequences
	baseHashes := make(map[uint32][]int)

	// Helper function to compute hash of a small window
	computeHash := func(data []byte, start int) uint32 {
		h := uint32(2166136261) // FNV offset basis
		for i := 0; i < hashWindow && start+i < len(data); i++ {
			h = (h ^ uint32(data[start+i])) * 16777619 // FNV prime
		}
		return h
	}

	// Build hash table for base content
	for i := 0; i <= len(base)-hashWindow; i++ {
		h := computeHash(base, i)
		baseHashes[h] = append(baseHashes[h], i)
	}

	// Find potential matches for each position in target
	for i := 0; i <= len(target)-hashWindow; i++ {
		h := computeHash(target, i)

		// Get base positions with matching hash
		basePositions, ok := baseHashes[h]
		if !ok {
			continue
		}

		// Check each potential match and extend it as far as possible
		for _, basePos := range basePositions {
			// Extend match forward
			matchLen := 0
			for basePos+matchLen < len(base) &&
				i+matchLen < len(target) &&
				base[basePos+matchLen] == target[i+matchLen] {
				matchLen++
			}

			// Only keep matches that are long enough
			if matchLen >= minMatchSize {
				matches[i] = append(matches[i], Match{
					BaseOffset:  basePos,
					MatchLength: matchLen,
				})
			}
		}
	}

	return matches
}

// computeDeltaWithCache computes delta operations using pre-computed match cache
func computeDeltaWithCache(buffer *bytes.Buffer, base, target []byte, matchCache map[int][]Match) error {
	const maxInsertSize = 127 // Maximum size for a single insert instruction

	pos := 0
	insertBuf := make([]byte, 0, maxInsertSize)

	// Flush any pending insert data
	flushInsert := func() {
		if len(insertBuf) > 0 {
			encodeInsertCommand(buffer, insertBuf)
			insertBuf = insertBuf[:0]
		}
	}

	for pos < len(target) {
		// Find the best match at current position
		var bestMatch *struct{ BaseOffset, Length int }

		if matches, ok := matchCache[pos]; ok && len(matches) > 0 {
			// Find the longest match
			longest := matches[0]
			for _, m := range matches {
				if m.MatchLength > longest.MatchLength {
					longest = m
				}
			}

			bestMatch = &struct{ BaseOffset, Length int }{
				BaseOffset: longest.BaseOffset,
				Length:     longest.MatchLength,
			}
		}

		if bestMatch != nil && bestMatch.Length >= 4 {
			// We found a good match - flush any pending insert and encode copy
			flushInsert()
			encodeCopyCommand(buffer, uint32(bestMatch.BaseOffset), uint32(bestMatch.Length))
			pos += bestMatch.Length
		} else {
			// No good match - add byte to insert buffer
			insertBuf = append(insertBuf, target[pos])
			pos++

			// If insert buffer is full, flush it
			if len(insertBuf) >= maxInsertSize {
				flushInsert()
			}
		}
	}

	// Flush any remaining insert data
	flushInsert()

	return nil
}
