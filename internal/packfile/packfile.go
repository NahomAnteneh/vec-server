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

	"github.com/NahomAnteneh/vec-server/core"
)

// Packfile represents a packfile with its objects and index
type Packfile struct {
	Repo     *core.Repository
	Header   PackFileHeader
	Objects  []Object
	Checksum [hashLength]byte
	Index    PackfileIndex
	filePath string
}

// NewPackfile creates a new Packfile instance
func NewPackfile(repo *core.Repository) *Packfile {
	return &Packfile{
		Repo:   repo,
		Header: PackFileHeader{Signature: [4]byte{'P', 'A', 'C', 'K'}, Version: 2},
	}
}

// Create builds a packfile from a list of object hashes
func (p *Packfile) Create(objectHashes []string, useDelta bool, outputPath string) error {
	if p.Repo == nil {
		return core.RepositoryError("nil repository", nil)
	}
	p.Objects = make([]Object, 0, len(objectHashes))
	p.filePath = outputPath
	p.Header.NumObjects = uint32(len(objectHashes))

	var buf bytes.Buffer
	h := sha256.New()

	// Write header
	if err := binary.Write(&buf, binary.BigEndian, &p.Header); err != nil {
		return core.ObjectError("failed to write header", err)
	}
	_, _ = h.Write([]byte("PACK"))
	_ = binary.Write(h, binary.BigEndian, p.Header.Version)
	_ = binary.Write(h, binary.BigEndian, p.Header.NumObjects)

	// Collect objects
	offset := int64(12) // Header size
	for _, hash := range objectHashes {
		objType, data, err := p.Repo.ReadObject(hash)
		if err != nil {
			return core.ObjectError(fmt.Sprintf("failed to read object %s", hash), err)
		}
		oType := StringToType(objType)
		if oType == OBJ_NONE {
			return core.ObjectError(fmt.Sprintf("unknown object type: %s", objType), nil)
		}
		hashBytes, err := hexToBytes(hash)
		if err != nil {
			return core.ObjectError(fmt.Sprintf("invalid hash format for %s", hash), err)
		}
		p.Objects = append(p.Objects, Object{
			Type:      oType,
			Size:      uint64(len(data)),
			Data:      data,
			Offset:    offset,
			Hash:      hash,
			HashBytes: hashBytes,
		})
	}

	// Apply delta compression
	if useDelta {
		if err := p.Optimize(); err != nil {
			return core.ObjectError("failed to optimize objects", err)
		}
	}

	// Write objects
	for i := range p.Objects {
		if err := p.writeObject(&buf, h, &p.Objects[i]); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to write object %d", i), err)
		}
	}

	// Write and verify checksum
	p.Checksum = sha256.Sum256(buf.Bytes())
	if _, err := buf.Write(p.Checksum[:]); err != nil {
		return core.ObjectError("failed to write checksum", err)
	}

	// Write to file if specified
	if outputPath != "" {
		if err := core.WriteFileContent(outputPath, buf.Bytes(), 0644); err != nil {
			return core.FSError(fmt.Sprintf("failed to write packfile %s", outputPath), err)
		}
	}

	return nil
}

// Parse reads a packfile from a file or byte slice
func (p *Packfile) Parse(input interface{}) error {
	var r io.Reader
	var filePath string
	switch v := input.(type) {
	case string:
		f, err := os.Open(v)
		if err != nil {
			return core.FSError(fmt.Sprintf("failed to open packfile %s", v), err)
		}
		defer f.Close()
		filePath = v
		r = f
	case []byte:
		r = bytes.NewReader(v)
	default:
		return core.ObjectError(fmt.Sprintf("invalid input type: %T", input), nil)
	}

	// Parse using parser.go logic
	objects, err := parsePackfileReader(r)
	if err != nil {
		return core.ObjectError("failed to parse packfile", err)
	}

	p.Objects = objects
	p.filePath = filePath

	// Recompute checksum
	var buf bytes.Buffer
	h := sha256.New()
	if err := binary.Write(&buf, binary.BigEndian, &p.Header); err != nil {
		return core.ObjectError("failed to compute checksum", err)
	}
	_, _ = h.Write([]byte("PACK"))
	_ = binary.Write(h, binary.BigEndian, p.Header.Version)
	_ = binary.Write(h, binary.BigEndian, p.Header.NumObjects)
	for i := range p.Objects {
		if err := p.writeObject(&buf, h, &p.Objects[i]); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to compute object %d checksum", i), err)
		}
	}
	p.Checksum = sha256.Sum256(buf.Bytes())

	return nil
}

// Optimize applies delta compression to objects
func (p *Packfile) Optimize() error {
	optimized, err := OptimizeObjects(p.Objects)
	if err != nil {
		return err
	}
	p.Objects = optimized
	return nil
}

// Finalize writes objects to the repository
func (p *Packfile) Finalize() error {
	if p.Repo == nil {
		return core.RepositoryError("nil repository", nil)
	}
	for _, obj := range p.Objects {
		objType := TypeToString(obj.Type)
		if objType == "delta" || objType == "none" || objType == "unknown" {
			continue
		}
		if _, err := p.Repo.WriteObject(objType, obj.Data); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to write object %s", obj.Hash), err)
		}
	}
	return nil
}

// Verify checks packfile integrity
func (p *Packfile) Verify() error {
	var buf bytes.Buffer
	h := sha256.New()

	if err := binary.Write(&buf, binary.BigEndian, &p.Header); err != nil {
		return core.ObjectError("failed to verify header", err)
	}
	_, _ = h.Write([]byte("PACK"))
	_ = binary.Write(h, binary.BigEndian, p.Header.Version)
	_ = binary.Write(h, binary.BigEndian, p.Header.NumObjects)

	for i, obj := range p.Objects {
		if err := p.writeObject(&buf, h, &obj); err != nil {
			return core.ObjectError(fmt.Sprintf("failed to verify object %d", i), err)
		}
	}
	computedChecksum := sha256.Sum256(buf.Bytes())
	if !bytes.Equal(p.Checksum[:], computedChecksum[:]) {
		return core.ObjectError("checksum verification failed", nil)
	}
	return nil
}

// ExtractObject retrieves an object by hash
func (p *Packfile) ExtractObject(hash string) (*Object, error) {
	hashBytes, err := hexToBytes(hash)
	if err != nil {
		return nil, core.ObjectError(fmt.Sprintf("invalid hash format: %s", hash), err)
	}
	for _, obj := range p.Objects {
		if bytes.Equal(obj.HashBytes[:], hashBytes[:]) {
			return &obj, nil
		}
	}
	return nil, core.NotFoundError(core.ErrCategoryObject, fmt.Sprintf("object %s", hash[:8]))
}

// writeObject writes a single object
func (p *Packfile) writeObject(w io.Writer, h io.Writer, obj *Object) error {
	tee := io.MultiWriter(w, h)
	var buf bytes.Buffer

	// Encode type and size
	typeAndSize := byte(obj.Type<<4) | 0x80
	if _, err := buf.Write([]byte{typeAndSize}); err != nil {
		return err
	}
	size := obj.Size
	shift := uint(4)
	for {
		b := byte(size & 0x7F)
		size >>= 7
		if size == 0 {
			if _, err := buf.Write([]byte{b}); err != nil {
				return err
			}
			break
		}
		if _, err := buf.Write([]byte{b | 0x80}); err != nil {
			return err
		}
		shift += 7
	}

	// Write delta-specific data
	if obj.Type == OBJ_OFS_DELTA {
		if obj.BaseIndex < 0 || obj.BaseIndex >= len(p.Objects) {
			return fmt.Errorf("invalid base index %d for delta object", obj.BaseIndex)
		}
		deltaOffset := obj.Offset - p.Objects[obj.BaseIndex].Offset
		var deltaBuf bytes.Buffer
		for {
			b := byte(deltaOffset & 0x7F)
			deltaOffset >>= 7
			if deltaOffset == 0 {
				deltaBuf.WriteByte(b)
				break
			}
			deltaBuf.WriteByte(b | 0x80)
		}
		if _, err := buf.Write(deltaBuf.Bytes()); err != nil {
			return err
		}
	} else if obj.Type == OBJ_REF_DELTA {
		if _, err := buf.Write(obj.BaseHashBytes[:]); err != nil {
			return err
		}
	}

	// Compress data
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return core.ObjectError("failed to create zlib writer", err)
	}
	if _, err := zw.Write(obj.Data); err != nil {
		zw.Close()
		return core.ObjectError("failed to write object data", err)
	}
	if err := zw.Close(); err != nil {
		return core.ObjectError("failed to close zlib writer", err)
	}

	_, err = buf.WriteTo(tee)
	return err
}

// hexToBytes converts a hex string to a byte array
func hexToBytes(hexStr string) ([hashLength]byte, error) {
	var result [hashLength]byte
	if len(hexStr) != hexHashLength {
		return result, fmt.Errorf("invalid hash length: %d", len(hexStr))
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, err
	}
	copy(result[:], bytes)
	return result, nil
}
