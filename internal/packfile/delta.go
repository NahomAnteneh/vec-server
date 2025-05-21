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
			encodeInsertCommand(&buffer, target[pos:pos+chunkSize])
			pos += chunkSize
		}
		return buffer.Bytes(), nil
	}

	// Main delta computation - more efficient with match caching for large objects
	matchCache := buildMatchCache(base, target)
	err := computeDeltaWithCache(&buffer, base, target, matchCache)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// encodeSize encodes a size value into a delta buffer
func encodeSize(buffer *bytes.Buffer, size uint64) {
	var bytes [10]byte // Maximum required for 64-bit value
	var i int

	for i = 0; i < 10; i++ {
		b := byte(size & 0x7F)
		size >>= 7
		if size > 0 {
			b |= 0x80 // Set MSB for continuation
		}
		bytes[i] = b
		if size == 0 {
			break
		}
	}

	buffer.Write(bytes[:i+1])
}

// computeDelta computes a delta between a base and target object
func computeDelta(buffer *bytes.Buffer, base, target []byte) error {
	targetPos := 0
	for targetPos < len(target) {
		// Find the longest match in the base
		offset, length := findLongestMatch(base, target[targetPos:])

		if length >= 4 { // Only use copy command if match is long enough
			// Write copy command
			err := encodeCopyCommand(buffer, offset, length)
			if err != nil {
				return err
			}
			targetPos += int(length)
		} else {
			// Insert a single byte if no good match
			insertLen := 1
			// Try to extend the insert if following bytes also don't match well
			for insertLen < 127 && insertLen < (len(target)-targetPos) {
				nextPos := targetPos + insertLen
				if nextPos < len(target) {
					_, nextMatchLen := findLongestMatch(base, target[nextPos:])
					if nextMatchLen >= 4 {
						break // Found a good match, stop inserting
					}
				}
				insertLen++
			}

			// Write insert command
			encodeInsertCommand(buffer, target[targetPos:targetPos+insertLen])
			targetPos += insertLen
		}
	}
	return nil
}

// findLongestMatch finds the longest match in the base object for a given target sequence
// Returns offset in base and length of the match
func findLongestMatch(base, target []byte) (offset, length uint32) {
	maxLength := uint32(0)
	maxOffset := uint32(0)

	// Simple implementation for initial version
	// More sophisticated approaches would use a suffix array or rolling hash
	for i := 0; i <= len(base)-4; i++ {
		// Only try matching if first 4 bytes match (simple optimization)
		if len(target) >= 4 && bytes.Equal(base[i:i+4], target[:4]) {
			// Try to extend the match
			matchLen := uint32(4)
			for int(matchLen) < min(len(base)-i, len(target)) {
				if base[i+int(matchLen)] != target[matchLen] {
					break
				}
				matchLen++
			}

			if matchLen > maxLength {
				maxLength = matchLen
				maxOffset = uint32(i)
			}
		}
	}

	return maxOffset, maxLength
}

// encodeCopyCommand encodes a copy instruction into the delta buffer
func encodeCopyCommand(buffer *bytes.Buffer, offset, length uint32) error {
	// Make sure values are within valid ranges
	if offset > 0xFFFFFFFF {
		return fmt.Errorf("offset too large for delta encoding: %d", offset)
	}
	if length > 0xFFFFFF {
		return fmt.Errorf("length too large for delta encoding: %d", length)
	}

	// 0x80 indicates a copy command; lower 7 bits encode which bytes to include
	commandByte := byte(0x80)

	// Determine which bytes we need to write (optimization)
	offsetBytes := []byte{
		byte(offset & 0xFF),
		byte((offset >> 8) & 0xFF),
		byte((offset >> 16) & 0xFF),
		byte((offset >> 24) & 0xFF),
	}

	lengthBytes := []byte{
		byte(length & 0xFF),
		byte((length >> 8) & 0xFF),
		byte((length >> 16) & 0xFF),
	}

	// Set bits for required offset bytes
	if offset != 0 {
		if offset < 0x100 {
			commandByte |= 0x01 // 1-byte offset
		} else if offset < 0x10000 {
			commandByte |= 0x02 // 2-byte offset
		} else if offset < 0x1000000 {
			commandByte |= 0x04 // 3-byte offset
		} else {
			commandByte |= 0x08 // 4-byte offset
		}
	}

	// Set bits for required length bytes
	if length != 0x10000 { // if length != default (64KB)
		if length < 0x100 {
			commandByte |= 0x10 // 1-byte length
		} else if length < 0x10000 {
			commandByte |= 0x20 // 2-byte length
		} else {
			commandByte |= 0x40 // 3-byte length
		}
	}

	// Write command byte
	buffer.WriteByte(commandByte)

	// Write offset bytes
	if commandByte&0x01 != 0 {
		buffer.WriteByte(offsetBytes[0])
	}
	if commandByte&0x02 != 0 {
		buffer.WriteByte(offsetBytes[1])
	}
	if commandByte&0x04 != 0 {
		buffer.WriteByte(offsetBytes[2])
	}
	if commandByte&0x08 != 0 {
		buffer.WriteByte(offsetBytes[3])
	}

	// Write length bytes
	if commandByte&0x10 != 0 {
		buffer.WriteByte(lengthBytes[0])
	}
	if commandByte&0x20 != 0 {
		buffer.WriteByte(lengthBytes[1])
	}
	if commandByte&0x40 != 0 {
		buffer.WriteByte(lengthBytes[2])
	}

	return nil
}

// encodeInsertCommand encodes an insert instruction into the delta buffer
func encodeInsertCommand(buffer *bytes.Buffer, data []byte) {
	if len(data) > 127 {
		// Insert commands are limited to 127 bytes in this implementation
		data = data[:127]
	}

	// Insert commands: the size is the command byte itself (0-127)
	buffer.WriteByte(byte(len(data)))
	buffer.Write(data)
}

// OptimizeObjects creates delta-compressed objects from a set of Git objects
func OptimizeObjects(objects []Object) ([]Object, error) {
	if len(objects) <= 1 {
		return objects, nil // Nothing to optimize
	}

	// Calculate similarities between all objects
	similarities := calculateSimilarities(objects)

	// Sort by similarity score (highest first)
	sortSimilarities(similarities)

	// Build delta chains
	deltaChains := buildDeltaChains(similarities, objects)

	// Convert chains into delta objects
	result := make([]Object, 0, len(objects))
	processed := make(map[string]bool)

	// First, add all base objects
	for _, chain := range deltaChains {
		// Skip if already processed
		if processed[chain.BaseHash] {
			continue
		}

		// Find the base object
		baseObj := findObjectByHash(objects, chain.BaseHash)
		if baseObj == nil {
			// Should not happen if chains are built correctly
			return nil, fmt.Errorf("base object with hash %s not found", chain.BaseHash)
		}

		// Add base object to result
		result = append(result, *baseObj)
		processed[chain.BaseHash] = true
	}

	// Then, add delta objects
	for _, chain := range deltaChains {
		baseObj := findObjectByHash(objects, chain.BaseHash)
		if baseObj == nil {
			return nil, fmt.Errorf("base object %s not found", chain.BaseHash)
		}

		// Create and add delta objects
		for _, deltaDesc := range chain.Deltas {
			// Skip if already processed
			if processed[deltaDesc.TargetHash] {
				continue
			}

			// Find the target object
			targetObj := findObjectByHash(objects, deltaDesc.TargetHash)
			if targetObj == nil {
				return nil, fmt.Errorf("target object %s not found", deltaDesc.TargetHash)
			}

			// Create delta
			delta, err := createDelta(baseObj.Data, targetObj.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to create delta for %s: %w", deltaDesc.TargetHash, err)
			}

			// Create a delta object
			deltaObj := Object{
				Hash:     targetObj.Hash,
				Type:     OBJ_REF_DELTA,
				Data:     delta,
				BaseHash: baseObj.Hash,
			}

			result = append(result, deltaObj)
			processed[deltaDesc.TargetHash] = true
		}
	}

	// Add any remaining objects
	for _, obj := range objects {
		if !processed[obj.Hash] {
			result = append(result, obj)
			processed[obj.Hash] = true
		}
	}

	return result, nil
}

// DeltaChain represents a sequence of delta objects with a common base
type DeltaChain struct {
	BaseHash string            // Hash of the base object
	Deltas   []DeltaDescriptor // Descriptors for delta objects built on this base
}

// DeltaDescriptor describes a delta object in the chain
type DeltaDescriptor struct {
	TargetHash      string  // Hash of the resulting object
	SimilarityScore float64 // Similarity score to the base
}

// ObjectSimilarity represents similarity between two objects
type ObjectSimilarity struct {
	Obj1Hash string  // Hash of first object
	Obj2Hash string  // Hash of second object
	Score    float64 // Similarity score (0.0-1.0)
}

// findObjectByHash finds an object by its hash in the given slice
func findObjectByHash(objects []Object, hash string) *Object {
	for i := range objects {
		if objects[i].Hash == hash {
			return &objects[i]
		}
	}
	return nil
}

// calculateSimilarities calculates similarity scores between all pairs of objects
func calculateSimilarities(objects []Object) []ObjectSimilarity {
	similarities := make([]ObjectSimilarity, 0, len(objects)*(len(objects)-1)/2)

	// Compare each pair of objects
	for i := 0; i < len(objects); i++ {
		for j := i + 1; j < len(objects); j++ {
			// Skip if objects are of different types
			if objects[i].Type != objects[j].Type {
				continue
			}

			// Calculate similarity score
			score := calculateSimilarityScore(objects[i].Data, objects[j].Data)

			// Store the similarity
			similarities = append(similarities, ObjectSimilarity{
				Obj1Hash: objects[i].Hash,
				Obj2Hash: objects[j].Hash,
				Score:    score,
			})

			// Also store in reverse direction
			similarities = append(similarities, ObjectSimilarity{
				Obj1Hash: objects[j].Hash,
				Obj2Hash: objects[i].Hash,
				Score:    score,
			})
		}
	}

	return similarities
}

// calculateSimilarityScore calculates a similarity score between two data blobs
func calculateSimilarityScore(data1, data2 []byte) float64 {
	// Different strategies for different sizes
	if len(data1) < 1000 && len(data2) < 1000 {
		return calculateSmallObjectSimilarity(data1, data2)
	}
	return calculateLargeObjectSimilarity(data1, data2)
}

// calculateSmallObjectSimilarity calculates similarity for small objects
// by comparing them directly
func calculateSmallObjectSimilarity(data1, data2 []byte) float64 {
	// Simple similarity based on common prefix and suffix
	commonPrefixLen := 0
	minLen := min(len(data1), len(data2))

	// Find common prefix
	for commonPrefixLen < minLen && data1[commonPrefixLen] == data2[commonPrefixLen] {
		commonPrefixLen++
	}

	// Find common suffix
	commonSuffixLen := 0
	for commonSuffixLen < minLen-commonPrefixLen {
		idx1 := len(data1) - 1 - commonSuffixLen
		idx2 := len(data2) - 1 - commonSuffixLen
		if idx1 < commonPrefixLen || idx2 < commonPrefixLen || data1[idx1] != data2[idx2] {
			break
		}
		commonSuffixLen++
	}

	// Calculate similarity as proportion of shared bytes
	commonBytes := commonPrefixLen + commonSuffixLen
	if commonBytes == 0 {
		return 0.0
	}

	similarity := float64(commonBytes) / float64(max(len(data1), len(data2)))
	return similarity
}

// calculateLargeObjectSimilarity calculates similarity for large objects
// using a fingerprinting approach
func calculateLargeObjectSimilarity(data1, data2 []byte) float64 {
	// Chunking size for fingerprinting
	chunkSize := 64

	// Create fingerprints
	fp1 := createFingerprintsAtSize(data1, chunkSize)
	fp2 := createFingerprintsAtSize(data2, chunkSize)

	// Calculate similarity from fingerprints
	return calculateFingerprintSimilarity(fp1, fp2)
}

// createFingerprintsAtSize creates content fingerprints for data
func createFingerprintsAtSize(data []byte, chunkSize int) map[uint64]struct{} {
	fingerprints := make(map[uint64]struct{})

	if len(data) < chunkSize {
		if len(data) > 0 {
			fingerprints[simpleHash(data)] = struct{}{}
		}
		return fingerprints
	}

	// Create fingerprints using a sliding window
	windowCount := len(data) - chunkSize + 1
	for i := 0; i < windowCount; i += chunkSize / 4 { // Overlap windows for better coverage
		chunk := data[i : i+chunkSize]
		hash := simpleHash(chunk)
		fingerprints[hash] = struct{}{}
	}

	return fingerprints
}

// calculateFingerprintSimilarity calculates similarity from fingerprint sets
func calculateFingerprintSimilarity(fp1, fp2 map[uint64]struct{}) float64 {
	// Count shared fingerprints
	sharedCount := 0
	for hash := range fp1 {
		if _, exists := fp2[hash]; exists {
			sharedCount++
		}
	}

	// Calculate Jaccard similarity: |A ∩ B| / |A ∪ B|
	totalCount := len(fp1) + len(fp2) - sharedCount
	if totalCount == 0 {
		return 0.0
	}

	return float64(sharedCount) / float64(totalCount)
}

// simpleHash creates a simple hash for a byte slice
func simpleHash(data []byte) uint64 {
	var hash uint64 = 14695981039346656037 // FNV-1a offset basis
	for _, b := range data {
		hash ^= uint64(b)
		hash *= 1099511628211 // FNV-1a prime
	}
	return hash
}

// sortSimilarities sorts similarities by score in descending order
func sortSimilarities(similarities []ObjectSimilarity) {
	sort.Slice(similarities, func(i, j int) bool {
		return similarities[i].Score > similarities[j].Score
	})
}

// buildDeltaChains builds chains of delta objects from similarity scores
func buildDeltaChains(similarities []ObjectSimilarity, objects []Object) []DeltaChain {
	// Threshold for delta compression (only use deltas if similarity is high enough)
	const similarityThreshold = 0.4

	// Keep track of objects that are already part of a chain
	processed := make(map[string]bool)

	// Map from base hash to chain
	chainsByBase := make(map[string]*DeltaChain)

	// Process similarities in order of score (highest first)
	for _, sim := range similarities {
		// Skip if similarity is too low
		if sim.Score < similarityThreshold {
			continue
		}

		// Skip if the target is already processed
		if processed[sim.Obj2Hash] {
			continue
		}

		// Get the object sizes
		obj1 := findObjectByHash(objects, sim.Obj1Hash)
		obj2 := findObjectByHash(objects, sim.Obj2Hash)

		if obj1 == nil || obj2 == nil {
			continue
		}

		// Potential base and target
		baseHash := sim.Obj1Hash
		targetHash := sim.Obj2Hash

		// Choose smaller object as base if similarity is similar
		if len(obj1.Data) > len(obj2.Data) && sim.Score > 0.8 {
			baseHash = sim.Obj2Hash
			targetHash = sim.Obj1Hash
		}

		// Skip if base is already processed (would create cyclic dependency)
		if processed[baseHash] {
			continue
		}

		// Get or create chain for this base
		chain, exists := chainsByBase[baseHash]
		if !exists {
			chain = &DeltaChain{
				BaseHash: baseHash,
				Deltas:   []DeltaDescriptor{},
			}
			chainsByBase[baseHash] = chain
		}

		// Add target to chain
		chain.Deltas = append(chain.Deltas, DeltaDescriptor{
			TargetHash:      targetHash,
			SimilarityScore: sim.Score,
		})

		// Mark target as processed
		processed[targetHash] = true
	}

	// Convert map to slice
	chains := make([]DeltaChain, 0, len(chainsByBase))
	for _, chain := range chainsByBase {
		chains = append(chains, *chain)
	}

	return chains
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

// buildMatchCache builds a cache of matches between base and target
// for more efficient delta computation
func buildMatchCache(base, target []byte) map[int][]Match {
	// Cache matches for each position in the target
	matchCache := make(map[int][]Match)

	// Simple rolling hash approach for finding matches
	// This can be significantly optimized for production use

	// Minimum match length to consider
	minMatchLen := 4

	// For each position in the target
	for targetPos := 0; targetPos <= len(target)-minMatchLen; targetPos++ {
		// Skip if we already found matches for this position
		if _, exists := matchCache[targetPos]; exists {
			continue
		}

		matches := []Match{}

		// For each potential match position in the base
		for basePos := 0; basePos <= len(base)-minMatchLen; basePos++ {
			// Check if the first few bytes match
			if bytes.Equal(target[targetPos:targetPos+minMatchLen], base[basePos:basePos+minMatchLen]) {
				// Potential match found, try to extend it
				matchLen := minMatchLen
				for targetPos+matchLen < len(target) &&
					basePos+matchLen < len(base) &&
					target[targetPos+matchLen] == base[basePos+matchLen] {
					matchLen++
				}

				// Record this match
				matches = append(matches, Match{
					BaseOffset:  basePos,
					MatchLength: matchLen,
				})
			}
		}

		// Sort matches by length (longest first)
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].MatchLength > matches[j].MatchLength
		})

		// Store matches for this position
		if len(matches) > 0 {
			// Only store the N best matches
			maxMatches := 5
			if len(matches) > maxMatches {
				matches = matches[:maxMatches]
			}
			matchCache[targetPos] = matches
		}
	}

	return matchCache
}

// computeDeltaWithCache computes a delta between base and target using a match cache
func computeDeltaWithCache(buffer *bytes.Buffer, base, target []byte, matchCache map[int][]Match) error {
	targetPos := 0

	for targetPos < len(target) {
		// Check if we have cached matches for this position
		matches, hasMatches := matchCache[targetPos]

		if hasMatches && len(matches) > 0 {
			// Use the first (best) match
			match := matches[0]

			// Only use the match if it's long enough
			if match.MatchLength >= 4 {
				// Write copy command
				err := encodeCopyCommand(buffer, uint32(match.BaseOffset), uint32(match.MatchLength))
				if err != nil {
					return err
				}
				targetPos += match.MatchLength
				continue
			}
		}

		// No good match, insert a byte
		insertEnd := targetPos + 1

		// Try to extend the insert if following bytes also don't match well
		for insertEnd < len(target) && (insertEnd-targetPos) < 127 {
			if _, hasNextMatches := matchCache[insertEnd]; hasNextMatches {
				// Stop at a position where we have a good match
				nextMatches := matchCache[insertEnd]
				if len(nextMatches) > 0 && nextMatches[0].MatchLength >= 4 {
					break
				}
			}
			insertEnd++
		}

		// Write insert command
		insertLen := insertEnd - targetPos
		if insertLen > 127 {
			insertLen = 127
		}

		encodeInsertCommand(buffer, target[targetPos:targetPos+insertLen])
		targetPos += insertLen
	}

	return nil
}
