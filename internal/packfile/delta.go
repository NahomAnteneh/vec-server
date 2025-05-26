package packfile

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

// OptimizeObjects creates delta objects to reduce storage size
func OptimizeObjects(objects []Object) ([]Object, error) {
	if len(objects) <= 1 {
		return objects, nil
	}

	// Calculate similarities
	similarities := calculateSimilarities(objects)

	// Sort by highest similarity
	sortSimilarities(similarities)

	// Build delta chains
	chains := buildDeltaChains(similarities, objects)

	// Create result
	result := make([]Object, 0, len(objects))
	processedHashes := make(map[string]bool)

	// Add base objects
	for _, chain := range chains {
		baseObj := findObjectByHash(objects, chain.BaseHash)
		if baseObj == nil {
			return nil, fmt.Errorf("base object not found: %s", chain.BaseHash)
		}
		if !processedHashes[baseObj.Hash] {
			result = append(result, *baseObj)
			processedHashes[baseObj.Hash] = true
		}

		// Process deltas
		for _, deltaDes := range chain.Deltas {
			targetObj := findObjectByHash(objects, deltaDes.TargetHash)
			if targetObj == nil {
				return nil, fmt.Errorf("target object not found: %s", deltaDes.TargetHash)
			}
			deltaData, err := createDelta(baseObj.Data, targetObj.Data)
			if err != nil {
				if !processedHashes[targetObj.Hash] {
					result = append(result, *targetObj)
					processedHashes[targetObj.Hash] = true
				}
				continue
			}
			if len(deltaData) >= len(targetObj.Data) {
				if !processedHashes[targetObj.Hash] {
					result = append(result, *targetObj)
					processedHashes[targetObj.Hash] = true
				}
				continue
			}
			baseHashBytes, _ := hexToBytes(baseObj.Hash)
			baseIndex := -1
			// Find the index of the base object in the result array
			for i, obj := range result {
				if obj.Hash == baseObj.Hash {
					baseIndex = i
					break
				}
			}
			deltaObj := Object{
				Hash:          targetObj.Hash,
				HashBytes:     targetObj.HashBytes,
				Type:          OBJ_REF_DELTA,
				Data:          deltaData,
				BaseHash:      baseObj.Hash,
				BaseHashBytes: baseHashBytes,
				Size:          uint64(len(deltaData)),
				BaseIndex:     baseIndex,
			}
			result = append(result, deltaObj)
			processedHashes[targetObj.Hash] = true
		}
	}

	// Add remaining objects
	for _, obj := range objects {
		if !processedHashes[obj.Hash] {
			result = append(result, obj)
			processedHashes[obj.Hash] = true
		}
	}

	return result, nil
}

// [Rest of delta.go remains unchanged from original, included for completeness]
type Match struct {
	BaseOffset  int
	MatchLength int
}

func applyDelta(base, delta []byte) ([]byte, error) {
	if len(delta) < 2 {
		return nil, errors.New("delta too short")
	}
	sourceSize, bytesRead := decodeSize(delta)
	delta = delta[bytesRead:]
	targetSize, bytesRead := decodeSize(delta)
	delta = delta[bytesRead:]
	if sourceSize != uint64(len(base)) {
		return nil, fmt.Errorf("source size mismatch: expected %d, got %d", len(base), sourceSize)
	}
	result := make([]byte, 0, targetSize)
	for len(delta) > 0 {
		cmd := delta[0]
		delta = delta[1:]
		if cmd == 0 {
			return nil, errors.New("invalid delta: zero command byte")
		} else if cmd&0x80 != 0 {
			var offset, size uint32
			if cmd&0x01 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset = uint32(delta[0])
				delta = delta[1:]
			}
			if cmd&0x02 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 8
				delta = delta[1:]
			}
			if cmd&0x04 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 16
				delta = delta[1:]
			}
			if cmd&0x08 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for offset")
				}
				offset |= uint32(delta[0]) << 24
				delta = delta[1:]
			}
			if cmd&0x10 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size = uint32(delta[0])
				delta = delta[1:]
			}
			if cmd&0x20 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size |= uint32(delta[0]) << 8
				delta = delta[1:]
			}
			if cmd&0x40 != 0 {
				if len(delta) < 1 {
					return nil, errors.New("delta too short for size")
				}
				size |= uint32(delta[0]) << 16
				delta = delta[1:]
			}
			if size == 0 {
				size = 0x10000
			}
			if offset+size > uint32(len(base)) {
				return nil, fmt.Errorf("invalid copy: offset %d + size %d > base length %d", offset, size, len(base))
			}
			result = append(result, base[offset:offset+size]...)
		} else {
			size := int(cmd)
			if len(delta) < size {
				return nil, errors.New("delta too short for insert data")
			}
			result = append(result, delta[:size]...)
			delta = delta[size:]
		}
	}
	if uint64(len(result)) != targetSize {
		return nil, fmt.Errorf("target size mismatch: expected %d, got %d", targetSize, len(result))
	}
	return result, nil
}

func decodeSize(delta []byte) (uint64, int) {
	var size uint64
	shift := uint(0)
	bytesRead := 0
	for {
		if bytesRead >= len(delta) {
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

func createDelta(base, target []byte) ([]byte, error) {
	var buffer bytes.Buffer
	encodeSize(&buffer, uint64(len(base)))
	encodeSize(&buffer, uint64(len(target)))
	if len(target) == 0 {
		return buffer.Bytes(), nil
	}
	if len(base) == 0 {
		pos := 0
		for pos < len(target) {
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
	matchCache := buildMatchCache(base, target)
	err := computeDeltaWithCache(&buffer, base, target, matchCache)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

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

func findLongestMatch(base, target []byte) (offset, length uint32) {
	if len(target) < 4 {
		return 0, 0
	}
	const (
		prime        = 16777619
		windowSize   = 4
		maxMatchSize = 64 * 1024
	)
	baseHashes := make(map[uint32][]uint32)
	computeHash := func(data []byte, start, end int) uint32 {
		h := uint32(2166136261)
		for i := start; i < end && i < len(data); i++ {
			h = (h ^ uint32(data[i])) * prime
		}
		return h
	}
	for i := 0; i <= len(base)-windowSize; i++ {
		h := computeHash(base, i, i+windowSize)
		baseHashes[h] = append(baseHashes[h], uint32(i))
	}
	targetHash := computeHash(target, 0, windowSize)
	bestLength := uint32(0)
	bestOffset := uint32(0)
	if candidates, ok := baseHashes[targetHash]; ok {
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
	if bestLength < 12 && len(target) >= 8 {
		largeWindowSize := 8
		largeBaseHashes := make(map[uint64][]uint32)
		computeLargeHash := func(data []byte, start, end int) uint64 {
			h := uint64(14695981039346656037)
			for i := start; i < end && i < len(data); i++ {
				h = (h ^ uint64(data[i])) * 1099511628211
			}
			return h
		}
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

func encodeCopyCommand(buffer *bytes.Buffer, offset, length uint32) {
	var cmd byte = 0x80
	var offsetBytes, sizeBytes [4]byte
	numOffsetBytes := 0
	numSizeBytes := 0
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
	if length != 0x10000 {
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
	buffer.WriteByte(cmd)
	for i := 0; i < numOffsetBytes; i++ {
		buffer.WriteByte(offsetBytes[i])
	}
	for i := 0; i < numSizeBytes; i++ {
		buffer.WriteByte(sizeBytes[i])
	}
}

func encodeInsertCommand(buffer *bytes.Buffer, data []byte) {
	const maxChunkSize = 127
	remaining := len(data)
	offset := 0
	for remaining > 0 {
		size := remaining
		if size > maxChunkSize {
			size = maxChunkSize
		}
		buffer.WriteByte(byte(size))
		buffer.Write(data[offset : offset+size])
		offset += size
		remaining -= size
	}
}

const (
	minDeltaSavings = 512
	maxChainDepth   = 5
	chunkSize       = 64
)

type DeltaChain struct {
	BaseHash string
	Deltas   []DeltaDescriptor
}

type DeltaDescriptor struct {
	TargetHash      string
	SimilarityScore float64
}

type ObjectSimilarity struct {
	Obj1Hash string
	Obj2Hash string
	Score    float64
}

func findObjectByHash(objects []Object, hash string) *Object {
	for i := range objects {
		if objects[i].Hash == hash {
			return &objects[i]
		}
	}
	return nil
}

func calculateSimilarities(objects []Object) []ObjectSimilarity {
	maxComparisons := 10000
	result := make([]ObjectSimilarity, 0)
	objectsByType := make(map[ObjectType][]Object)
	for _, obj := range objects {
		objectsByType[obj.Type] = append(objectsByType[obj.Type], obj)
	}
doneComparing:
	for _, typeObjects := range objectsByType {
		sort.Slice(typeObjects, func(i, j int) bool {
			return len(typeObjects[i].Data) < len(typeObjects[j].Data)
		})
		comparisons := 0
		for i := 0; i < len(typeObjects); i++ {
			maxPerObject := 50
			if typeObjects[i].Type == OBJ_BLOB {
				maxPerObject = 20
			}
			comparisonCount := 0
			for j := i + 1; j < len(typeObjects) && comparisonCount < maxPerObject; j++ {
				sizeRatio := float64(len(typeObjects[i].Data)) / float64(len(typeObjects[j].Data))
				if sizeRatio < 0.5 || sizeRatio > 2.0 {
					continue
				}
				score := calculateSimilarityScore(typeObjects[i].Data, typeObjects[j].Data)
				if score > 0.3 {
					result = append(result, ObjectSimilarity{
						Obj1Hash: typeObjects[i].Hash,
						Obj2Hash: typeObjects[j].Hash,
						Score:    score,
					})
				}
				comparisonCount++
				comparisons++
				if comparisons >= maxComparisons {
					break doneComparing
				}
			}
		}
	}
	return result
}

func calculateSimilarityScore(data1, data2 []byte) float64 {
	if bytes.Equal(data1, data2) {
		return 1.0
	}
	sizeRatio := float64(min(len(data1), len(data2))) / float64(max(len(data1), len(data2)))
	if sizeRatio < 0.3 {
		return sizeRatio * 0.5
	}
	if len(data1) < 4096 && len(data2) < 4096 {
		return calculateSmallObjectSimilarity(data1, data2)
	}
	return calculateLargeObjectSimilarity(data1, data2)
}

func calculateSmallObjectSimilarity(data1, data2 []byte) float64 {
	const shingleSize = 4
	createShingles := func(data []byte) map[string]struct{} {
		shingles := make(map[string]struct{})
		if len(data) < shingleSize {
			shingles[string(data)] = struct{}{}
			return shingles
		}
		for i := 0; i <= len(data)-shingleSize; i++ {
			shingle := string(data[i : i+shingleSize])
			shingles[shingle] = struct{}{}
		}
		return shingles
	}
	shingles1 := createShingles(data1)
	shingles2 := createShingles(data2)
	commonCount := 0
	for shingle := range shingles1 {
		if _, exists := shingles2[shingle]; exists {
			commonCount++
		}
	}
	totalShingles := len(shingles1) + len(shingles2) - commonCount
	if totalShingles == 0 {
		return 0.0
	}
	return float64(commonCount) / float64(totalShingles)
}

func calculateLargeObjectSimilarity(data1, data2 []byte) float64 {
	smallFP1 := createFingerprintsAtSize(data1, 64)
	smallFP2 := createFingerprintsAtSize(data2, 64)
	mediumFP1 := createFingerprintsAtSize(data1, 256)
	mediumFP2 := createFingerprintsAtSize(data2, 256)
	largeFP1 := createFingerprintsAtSize(data1, 1024)
	largeFP2 := createFingerprintsAtSize(data2, 1024)
	smallSim := calculateFingerprintSimilarity(smallFP1, smallFP2)
	mediumSim := calculateFingerprintSimilarity(mediumFP1, mediumFP2)
	largeSim := calculateFingerprintSimilarity(largeFP1, largeFP2)
	return smallSim*0.2 + mediumSim*0.3 + largeSim*0.5
}

func createFingerprintsAtSize(data []byte, chunkSize int) map[uint64]struct{} {
	result := make(map[uint64]struct{})
	if len(data) < chunkSize {
		result[simpleHash(data)] = struct{}{}
		return result
	}
	numSamples := 100
	if len(data) < chunkSize*numSamples {
		step := max(1, chunkSize/4)
		for i := 0; i <= len(data)-chunkSize; i += step {
			chunk := data[i : i+chunkSize]
			result[simpleHash(chunk)] = struct{}{}
		}
	} else {
		step := (len(data) - chunkSize) / numSamples
		for i := 0; i < len(data)-chunkSize; i += step {
			chunk := data[i : i+chunkSize]
			result[simpleHash(chunk)] = struct{}{}
		}
		if len(data) >= chunkSize*2 {
			result[simpleHash(data[:chunkSize])] = struct{}{}
			result[simpleHash(data[len(data)-chunkSize:])] = struct{}{}
		}
	}
	return result
}

func calculateFingerprintSimilarity(fp1, fp2 map[uint64]struct{}) float64 {
	commonCount := 0
	for h := range fp1 {
		if _, exists := fp2[h]; exists {
			commonCount++
		}
	}
	totalCount := len(fp1) + len(fp2) - commonCount
	if totalCount == 0 {
		return 0.0
	}
	return float64(commonCount) / float64(totalCount)
}

func simpleHash(data []byte) uint64 {
	h := uint64(0)
	for i, b := range data {
		h = h*31 + uint64(b)
		if i > 1000 {
			break
		}
	}
	return h
}

func sortSimilarities(similarities []ObjectSimilarity) {
	sort.Slice(similarities, func(i, j int) bool {
		return similarities[i].Score > similarities[j].Score
	})
}

func buildDeltaChains(similarities []ObjectSimilarity, objects []Object) []DeltaChain {
	objectSizes := make(map[string]int)
	objectTypes := make(map[string]ObjectType)
	for _, obj := range objects {
		objectSizes[obj.Hash] = len(obj.Data)
		objectTypes[obj.Hash] = obj.Type
	}
	isBaseObject := make(map[string]bool)
	isDeltaObject := make(map[string]bool)
	chains := make(map[string]*DeltaChain)
	deltaGraph := make(map[string]map[string]float64)
	for _, sim := range similarities {
		if sim.Score < 0.1 {
			continue
		}
		if deltaGraph[sim.Obj1Hash] == nil {
			deltaGraph[sim.Obj1Hash] = make(map[string]float64)
		}
		if deltaGraph[sim.Obj2Hash] == nil {
			deltaGraph[sim.Obj2Hash] = make(map[string]float64)
		}
		deltaGraph[sim.Obj1Hash][sim.Obj2Hash] = sim.Score
		deltaGraph[sim.Obj2Hash][sim.Obj1Hash] = sim.Score
	}
	allObjects := make([]string, 0, len(objectSizes))
	for hash := range objectSizes {
		allObjects = append(allObjects, hash)
	}
	sort.Slice(allObjects, func(i, j int) bool {
		hashI, hashJ := allObjects[i], allObjects[j]
		typeI, typeJ := objectTypes[hashI], objectTypes[hashJ]
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
		return objectSizes[hashI] < objectSizes[hashJ]
	})
	estimateDeltaSize := func(baseHash, targetHash string) int {
		score := deltaGraph[baseHash][targetHash]
		estimatedSavings := int(float64(objectSizes[targetHash]) * score * 0.8)
		return objectSizes[targetHash] - estimatedSavings
	}
	for _, candidateBase := range allObjects {
		if isDeltaObject[candidateBase] {
			continue
		}
		potentialDeltas := make([]string, 0)
		for targetHash, score := range deltaGraph[candidateBase] {
			if score < 0.1 || isDeltaObject[targetHash] {
				continue
			}
			deltaSize := estimateDeltaSize(candidateBase, targetHash)
			if deltaSize >= objectSizes[targetHash] {
				continue
			}
			potentialDeltas = append(potentialDeltas, targetHash)
		}
		sort.Slice(potentialDeltas, func(i, j int) bool {
			targetI, targetJ := potentialDeltas[i], potentialDeltas[j]
			savingsI := objectSizes[targetI] - estimateDeltaSize(candidateBase, targetI)
			savingsJ := objectSizes[targetJ] - estimateDeltaSize(candidateBase, targetJ)
			return savingsI > savingsJ
		})
		if len(potentialDeltas) > 0 {
			chain := &DeltaChain{
				BaseHash: candidateBase,
				Deltas:   []DeltaDescriptor{},
			}
			isBaseObject[candidateBase] = true
			for _, targetHash := range potentialDeltas {
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
			if len(chain.Deltas) > 0 {
				chains[candidateBase] = chain
			}
		}
	}
	result := make([]DeltaChain, 0, len(chains))
	for _, chain := range chains {
		result = append(result, *chain)
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildMatchCache(base, target []byte) map[int][]Match {
	const (
		minMatchSize = 4
		hashWindow   = 4
	)
	matches := make(map[int][]Match)
	baseHashes := make(map[uint32][]int)
	computeHash := func(data []byte, start int) uint32 {
		h := uint32(2166136261)
		for i := 0; i < hashWindow && start+i < len(data); i++ {
			h = (h ^ uint32(data[start+i])) * 16777619
		}
		return h
	}
	for i := 0; i <= len(base)-hashWindow; i++ {
		h := computeHash(base, i)
		baseHashes[h] = append(baseHashes[h], i)
	}
	for i := 0; i <= len(target)-hashWindow; i++ {
		h := computeHash(target, i)
		basePositions, ok := baseHashes[h]
		if !ok {
			continue
		}
		for _, basePos := range basePositions {
			matchLen := 0
			for basePos+matchLen < len(base) && i+matchLen < len(target) && base[basePos+matchLen] == target[i+matchLen] {
				matchLen++
			}
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

func computeDeltaWithCache(buffer *bytes.Buffer, base, target []byte, matchCache map[int][]Match) error {
	const maxInsertSize = 127
	pos := 0
	insertBuf := make([]byte, 0, maxInsertSize)
	flushInsert := func() {
		if len(insertBuf) > 0 {
			encodeInsertCommand(buffer, insertBuf)
			insertBuf = insertBuf[:0]
		}
	}
	for pos < len(target) {
		var bestMatch *struct{ BaseOffset, Length int }
		if matches, ok := matchCache[pos]; ok && len(matches) > 0 {
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
			flushInsert()
			encodeCopyCommand(buffer, uint32(bestMatch.BaseOffset), uint32(bestMatch.Length))
			pos += bestMatch.Length
		} else {
			insertBuf = append(insertBuf, target[pos])
			pos++
			if len(insertBuf) >= maxInsertSize {
				flushInsert()
			}
		}
	}
	flushInsert()
	return nil
}
