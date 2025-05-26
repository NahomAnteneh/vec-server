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
	var idx PackfileIndex
	idx.Fanout = [256]uint32{}
	idx.Offsets = make([]uint32, len(p.Objects))
	idx.Hashes = make([][hashLength]byte, len(p.Objects))
	idx.CRCs = make([]uint32, len(p.Objects))
	idx.PackChecksum = p.Checksum

	// Populate index
	for i, obj := range p.Objects {
		idx.Offsets[i] = uint32(obj.Offset)
		idx.Hashes[i] = obj.HashBytes
		idx.CRCs[i] = crc32.ChecksumIEEE(obj.Data)
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
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(p.Objects[i].HashBytes[:], p.Objects[j].HashBytes[:]) < 0
	})
	for i, entry := range entries {
		idx.Offsets[i] = uint32(entry.Offset)
		idx.Hashes[i] = p.Objects[i].HashBytes
		idx.CRCs[i] = entry.CRC32
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
		if _, err := buf.Write(hash[:]); err != nil {
			return core.ObjectError("failed to write hash", err)
		}
	}
	for _, crc := range idx.CRCs {
		if err := binary.Write(&buf, binary.BigEndian, crc); err != nil {
			return core.ObjectError("failed to write CRC", err)
		}
	}
	if _, err := buf.Write(idx.PackChecksum[:]); err != nil {
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
		return core.ObjectError("invalid index header", nil)
	}

	if err := binary.Read(buf, binary.BigEndian, &idx.Fanout); err != nil {
		return core.ObjectError("failed to read fanout", err)
	}

	numObjects := idx.Fanout[255]
	idx.Offsets = make([]uint32, numObjects)
	idx.Hashes = make([][hashLength]byte, numObjects)
	idx.CRCs = make([]uint32, numObjects)

	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(buf, binary.BigEndian, &idx.Offsets[i]); err != nil {
			return core.ObjectError("failed to read offset", err)
		}
	}
	for i := uint32(0); i < numObjects; i++ {
		var hash [hashLength]byte
		if _, err := io.ReadFull(buf, hash[:]); err != nil {
			return core.ObjectError("failed to read hash", err)
		}
		idx.Hashes[i] = hash
	}
	for i := uint32(0); i < numObjects; i++ {
		if err := binary.Read(buf, binary.BigEndian, &idx.CRCs[i]); err != nil {
			return core.ObjectError("failed to read CRC", err)
		}
	}
	if _, err := io.ReadFull(buf, idx.PackChecksum[:]); err != nil {
		return core.ObjectError("failed to read pack checksum", err)
	}

	p.Index = idx
	return nil
}
