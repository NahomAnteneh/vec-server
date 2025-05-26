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
func parsePackfileReader(r io.Reader) ([]Object, error) {
	// Read and verify header
	var header PackFileHeader
	if err := binary.Read(r, binary.BigEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read packfile header: %w", err)
	}
	if string(header.Signature[:]) != "PACK" || header.Version != 2 {
		return nil, fmt.Errorf("invalid packfile header")
	}

	f, ok := r.(*os.File)
	if !ok {
		// For non-file readers, copy to temp file
		tmp, err := os.CreateTemp("", "packfile")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, r); err != nil {
			tmp.Close()
			return nil, fmt.Errorf("failed to copy to temp file: %w", err)
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			return nil, fmt.Errorf("failed to seek temp file: %w", err)
		}
		f = tmp
		defer f.Close()
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
	_, err := f.Seek(12, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek header: %w", err)
	}
	for i := uint32(0); i < header.NumObjects; i++ {
		pos, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get position: %w", err)
		}
		headerByte, err := readByte(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		objType := ObjectType((headerByte >> 4) & 0x7)
		info := objectInfo{offset: pos}
		if objType == OBJ_REF_DELTA {
			info.isDelta = true
			baseHashBytes := make([]byte, hashLength)
			if _, err := io.ReadFull(f, baseHashBytes); err != nil {
				return nil, fmt.Errorf("failed to read base hash: %w", err)
			}
			info.baseHash = hex.EncodeToString(baseHashBytes)
		} else if objType == OBJ_OFS_DELTA {
			info.isDelta = true
			var baseOffset uint64
			var b byte = 0x80
			var j uint
			for b&0x80 != 0 {
				b, err = readByte(f)
				if err != nil {
					return nil, fmt.Errorf("failed to read delta offset: %w", err)
				}
				baseOffset |= uint64(b&0x7F) << (j * 7)
				j++
			}
			info.basePos = pos - int64(baseOffset)
		}
		objectInfos[uint64(i)] = info
		zr, err := zlib.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader: %w", err)
		}
		_, err = io.Copy(io.Discard, zr)
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to skip data: %w", err)
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
			_, err = f.Seek(info.offset, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("failed to seek object: %w", err)
			}
			obj, err := readPackObject(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read object: %w", err)
			}
			hash := calculateObjectHash(obj.Type, obj.Data)
			hashBytes, _ := hexToBytes(hash)
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

	// Sort delta objects
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

	// Third pass: resolve deltas
	for _, d := range deltaObjects {
		info := d.info
		_, err = f.Seek(info.offset, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek delta: %w", err)
		}
		deltaObj, err := readPackObject(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read delta: %w", err)
		}
		if !(deltaObj.Type == OBJ_REF_DELTA || deltaObj.Type == OBJ_OFS_DELTA) {
			return nil, fmt.Errorf("expected delta at offset %d, got %s", info.offset, TypeToString(deltaObj.Type))
		}
		var baseObj *Object
		if info.baseHash != "" {
			for i := range objects {
				if objects[i].Hash == info.baseHash {
					baseObj = &objects[i]
					break
				}
			}
		} else {
			baseObj = objectsByOffset[info.basePos]
		}
		if baseObj == nil {
			return nil, fmt.Errorf("base object not found for delta at offset %d", info.offset)
		}
		resultData, err := applyDelta(baseObj.Data, deltaObj.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to apply delta: %w", err)
		}
		resultObj := Object{
			Type:   baseObj.Type,
			Data:   resultData,
			Offset: info.offset,
			Size:   uint64(len(resultData)),
		}
		hash := calculateObjectHash(resultObj.Type, resultObj.Data)
		hashBytes, _ := hexToBytes(hash)
		resultObj.Hash = hash
		resultObj.HashBytes = hashBytes
		objects = append(objects, resultObj)
		objectsByOffset[info.offset] = &objects[len(objects)-1]
	}

	return objects, nil
}

// readPackObject reads a single object
func readPackObject(f *os.File) (*Object, error) {
	headerByte, err := readByte(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	objType := ObjectType((headerByte >> 4) & 0x7)
	size := uint64(headerByte & 0x0F)
	shift := uint(4)
	for headerByte&0x80 != 0 {
		headerByte, err = readByte(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read size: %w", err)
		}
		size |= uint64(headerByte&0x7F) << shift
		shift += 7
	}
	var baseHash string
	var baseHashBytes [hashLength]byte
	if objType == OBJ_REF_DELTA {
		hashBytes := make([]byte, hashLength)
		if _, err := io.ReadFull(f, hashBytes); err != nil {
			return nil, fmt.Errorf("failed to read base hash: %w", err)
		}
		baseHash = hex.EncodeToString(hashBytes)
		copy(baseHashBytes[:], hashBytes)
	} else if objType == OBJ_OFS_DELTA {
		var b byte = 0x80
		for b&0x80 != 0 {
			b, err = readByte(f)
			if err != nil {
				return nil, fmt.Errorf("failed to read delta offset: %w", err)
			}
		}
	}
	zr, err := zlib.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zr.Close()
	var data bytes.Buffer
	if _, err := io.Copy(&data, zr); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return &Object{
		Type:          objType,
		Data:          data.Bytes(),
		BaseHash:      baseHash,
		BaseHashBytes: baseHashBytes,
		Size:          size,
	}, nil
}

// readByte reads a single byte
func readByte(f *os.File) (byte, error) {
	var b [1]byte
	_, err := f.Read(b[:])
	return b[0], err
}

// calculateObjectHash generates a SHA-256 hash
func calculateObjectHash(objType ObjectType, data []byte) string {
	typeStr := TypeToString(objType)
	if typeStr == "delta" || typeStr == "none" {
		typeStr = "blob" // Default for hashing
	}
	header := fmt.Sprintf("%s %d\x00", typeStr, len(data))
	hasher := sha256.New()
	hasher.Write([]byte(header))
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
