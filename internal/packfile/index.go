package packfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"

	"github.com/NahomAnteneh/vec-server/core"
)

// WriteIndex generates and writes the packfile index
func (p *Packfile) WriteIndex(outputPath string) error {
	if p.HashLength <= 0 {
		return core.ObjectError("invalid hash length", nil)
	}

	var idx PackfileIndex
	idx.Fanout = [256]uint32{}
	idx.Offsets = make([]uint32, len(p.Objects))
	idx.Hashes = make([][]byte, len(p.Objects))
	idx.CRCs = make([]uint32, len(p.Objects))
	idx.PackChecksum = p.Checksum

	// Populate index
	for i, obj := range p.Objects {
		if obj.Offset < 0 {
			return core.ObjectError(fmt.Sprintf("invalid negative offset %d for object %s", obj.Offset, obj.Hash), nil)
		}

		// Validate hash bytes
		if len(obj.HashBytes) != p.HashLength {
			return core.ObjectError(fmt.Sprintf("invalid hash length for object %s: got %d, expected %d",
				obj.Hash, len(obj.HashBytes), p.HashLength), nil)
		}

		idx.Offsets[i] = uint32(obj.Offset)
		idx.Hashes[i] = obj.HashBytes
		idx.CRCs[i] = crc32.ChecksumIEEE(obj.Data)

		// Ensure the first byte is valid for fanout index
		if len(obj.HashBytes) == 0 {
			return core.ObjectError(fmt.Sprintf("empty hash bytes for object %s", obj.Hash), nil)
		}

		idx.Fanout[obj.HashBytes[0]]++
	}

	// Compute fanout
	for i := 1; i < 256; i++ {
		idx.Fanout[i] += idx.Fanout[i-1]
	}

	// Sort by hash
	entries := make([]PackIndexEntry, len(p.Objects))
	for i := range p.Objects {
		entries[i] = PackIndexEntry{
			Offset: uint64(idx.Offsets[i]),
			Type:   p.Objects[i].Type,
			Size:   p.Objects[i].Size,
			CRC32:  idx.CRCs[i],
		}
	}

	// Create a copy of objects and hashes for sorting
	sortedObjects := make([]Object, len(p.Objects))
	copy(sortedObjects, p.Objects)

	sort.Slice(sortedObjects, func(i, j int) bool {
		return bytes.Compare(sortedObjects[i].HashBytes, sortedObjects[j].HashBytes) < 0
	})

	// Update index with sorted values
	for i, obj := range sortedObjects {
		idx.Offsets[i] = uint32(obj.Offset)
		idx.Hashes[i] = obj.HashBytes
		idx.CRCs[i] = crc32.ChecksumIEEE(obj.Data)
	}

	// Write index
	var buf bytes.Buffer
	header := [8]byte{0xFF, 0x74, 0x4F, 0x63, 0x00, 0x00, 0x00, 0x02}
	if _, err := buf.Write(header[:]); err != nil {
		return core.ObjectError("failed to write index header", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, idx.Fanout); err != nil {
		return core.ObjectError("failed to write fanout", err)
	}
	for _, offset := range idx.Offsets {
		if err := binary.Write(&buf, binary.BigEndian, offset); err != nil {
			return core.ObjectError("failed to write offset", err)
		}
	}
	for _, hash := range idx.Hashes {
		if len(hash) != p.HashLength {
			return core.ObjectError(fmt.Sprintf("invalid hash length in index: got %d, expected %d",
				len(hash), p.HashLength), nil)
		}
		if _, err := buf.Write(hash); err != nil {
			return core.ObjectError("failed to write hash", err)
		}
	}
	for _, crc := range idx.CRCs {
		if err := binary.Write(&buf, binary.BigEndian, crc); err != nil {
			return core.ObjectError("failed to write CRC", err)
		}
	}

	if len(idx.PackChecksum) != p.HashLength {
		return core.ObjectError(fmt.Sprintf("invalid pack checksum length: got %d, expected %d",
			len(idx.PackChecksum), p.HashLength), nil)
	}

	if _, err := buf.Write(idx.PackChecksum); err != nil {
		return core.ObjectError("failed to write pack checksum", err)
	}

	if outputPath != "" {
		if err := core.WriteFileContent(outputPath, buf.Bytes(), 0644); err != nil {
			return core.FSError(fmt.Sprintf("failed to write index %s", outputPath), err)
		}
	}

	p.Index = idx
	return nil
}

// ReadIndex reads the packfile index
func (p *Packfile) ReadIndex(inputPath string) error {
	if p.HashLength <= 0 {
		return core.ObjectError("invalid hash length", nil)
	}

	data, err := core.ReadFileContent(inputPath)
	if err != nil {
		return core.FSError(fmt.Sprintf("failed to read index %s", inputPath), err)
	}

	buf := bytes.NewReader(data)
	var idx PackfileIndex

	var header [8]byte
	if _, err := io.ReadFull(buf, header[:]); err != nil {
		return core.ObjectError("failed to read index header", err)
	}
	if string(header[:4]) != "\xFFtOc" || binary.BigEndian.Uint32(header[4:]) != 2 {
		return core.ObjectError(fmt.Sprintf("invalid index header: %x", header[:]), nil)
	}

	if err := binary.Read(buf, binary.BigEndian, &idx.Fanout); err != nil {
		return core.ObjectError("failed to read fanout", err)
	}

	numObjects := idx.Fanout[255]
	if numObjects == 0 {
		// Empty index
		p.Index = idx
		return nil
	}

	idx.Offsets = make([]uint32, numObjects)
	idx.Hashes = make([][]byte, numObjects)
	idx.CRCs = make([]uint32, numObjects)

	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(buf, binary.BigEndian, &idx.Offsets[i]); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to read offset for object %d", i), err)
		}
	}

	for i := uint32(0); i < numObjects; i++ {
		hash := make([]byte, p.HashLength)
		if _, err := io.ReadFull(buf, hash); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to read hash for object %d", i), err)
		}
		idx.Hashes[i] = hash
	}

	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(buf, binary.BigEndian, &idx.CRCs[i]); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to read CRC for object %d", i), err)
		}
	}

	// Read pack checksum
	idx.PackChecksum = make([]byte, p.HashLength)
	if _, err := io.ReadFull(buf, idx.PackChecksum); err != nil {
		return core.ObjectError("failed to read pack checksum", err)
	}

	p.Index = idx
	return nil
}
