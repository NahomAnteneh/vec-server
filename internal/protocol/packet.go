package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxPktSize is the maximum size of a packet (65516 bytes)
	MaxPktSize = 65516
	// PktLenSize is the size of the packet length prefix (4 bytes)
	PktLenSize = 4
	// FlushPkt is the special flush packet "0000"
	FlushPkt = "0000"
)

// Common errors
var (
	ErrPacketTooLarge = errors.New("packet exceeds maximum allowed size")
	ErrInvalidPacket  = errors.New("invalid packet format")
	ErrEmptyPacket    = errors.New("empty packet")
)

// EncodePacketLine encodes data into packet-line format, adding the length prefix
func EncodePacketLine(data []byte) ([]byte, error) {
	// Check if data fits in a packet
	if len(data) > MaxPktSize-PktLenSize {
		return nil, ErrPacketTooLarge
	}

	// Create buffer with length prefix
	length := len(data) + PktLenSize
	prefix := fmt.Sprintf("%04x", length)

	// Combine prefix with data
	result := make([]byte, PktLenSize+len(data))
	copy(result[:PktLenSize], prefix)
	copy(result[PktLenSize:], data)

	return result, nil
}

// DecodePacketLine decodes a packet from the reader
// Returns the packet data without the length prefix, an error, and a boolean indicating if it's a flush packet
func DecodePacketLine(r io.Reader) ([]byte, bool, error) {
	// Read the 4-byte length prefix
	prefix := make([]byte, PktLenSize)
	n, err := io.ReadFull(r, prefix)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read packet length: %w", err)
	}
	if n != PktLenSize {
		return nil, false, ErrInvalidPacket
	}

	// Check for flush packet
	if bytes.Equal(prefix, []byte(FlushPkt)) {
		return nil, true, nil
	}

	// Parse the length
	lengthStr := string(prefix)
	length, err := hex.DecodeString(lengthStr)
	if err != nil || len(length) != 2 {
		return nil, false, fmt.Errorf("invalid packet length: %w", err)
	}

	// The length includes the 4-byte prefix itself
	dataLength := (int(length[0]) << 8) | int(length[1]) - PktLenSize
	if dataLength <= 0 {
		return nil, false, ErrEmptyPacket
	}

	// Read the data
	data := make([]byte, dataLength)
	n, err = io.ReadFull(r, data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read packet data: %w", err)
	}
	if n != dataLength {
		return nil, false, ErrInvalidPacket
	}

	return data, false, nil
}

// WritePacketLine writes data in packet-line format to the writer
func WritePacketLine(w io.Writer, data []byte) error {
	encoded, err := EncodePacketLine(data)
	if err != nil {
		return err
	}

	_, err = w.Write(encoded)
	return err
}

// ReadPacketLine reads a single packet from the reader and returns its data
func ReadPacketLine(r io.Reader) ([]byte, bool, error) {
	return DecodePacketLine(r)
}

// WriteFlushPacket writes a flush packet to the writer
func WriteFlushPacket(w io.Writer) error {
	_, err := w.Write([]byte(FlushPkt))
	return err
}

// ReadAllPacketLines reads all packet lines until a flush packet is encountered
func ReadAllPacketLines(r io.Reader) ([][]byte, error) {
	var packets [][]byte

	for {
		data, isFlush, err := ReadPacketLine(r)
		if err != nil {
			return packets, err
		}

		if isFlush {
			break
		}

		packets = append(packets, data)
	}

	return packets, nil
}

// WriteAllPacketLines writes multiple packet lines and a final flush packet
func WriteAllPacketLines(w io.Writer, packets [][]byte) error {
	for _, data := range packets {
		if err := WritePacketLine(w, data); err != nil {
			return err
		}
	}

	return WriteFlushPacket(w)
}
