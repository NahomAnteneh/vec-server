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

	// SideBandMain is the channel for packfile data
	SideBandMain = 1
	// SideBandProgress is the channel for progress information
	SideBandProgress = 2
	// SideBandError is the channel for error messages
	SideBandError = 3
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

// EncodeSideBand encodes data for side-band transmission on the specified channel
func EncodeSideBand(channel byte, data []byte) []byte {
	result := make([]byte, len(data)+1)
	result[0] = channel
	copy(result[1:], data)
	return result
}

// DecodeSideBand decodes side-band data and returns the channel and data
func DecodeSideBand(data []byte) (byte, []byte, error) {
	if len(data) < 1 {
		return 0, nil, errors.New("invalid side-band data")
	}

	channel := data[0]
	payload := data[1:]

	return channel, payload, nil
}

// WriteSideBand writes data on the specified side-band channel
func WriteSideBand(w io.Writer, channel byte, data []byte) error {
	return WritePacketLine(w, EncodeSideBand(channel, data))
}

// ReadSideBand reads data from a side-band encoded packet
func ReadSideBand(r io.Reader) (byte, []byte, bool, error) {
	data, isFlush, err := ReadPacketLine(r)
	if err != nil {
		return 0, nil, isFlush, err
	}

	if isFlush {
		return 0, nil, true, nil
	}

	channel, payload, err := DecodeSideBand(data)
	if err != nil {
		return 0, nil, false, err
	}

	return channel, payload, false, nil
}

// WriteDelimitedPacket writes a packet with null-terminated capabilities
func WriteDelimitedPacket(w io.Writer, first string, capabilities string) error {
	data := []byte(first)
	if capabilities != "" {
		data = append(data, 0) // Null delimiter
		data = append(data, []byte(capabilities)...)
	}
	return WritePacketLine(w, data)
}

// ParseCapabilities parses capabilities from a want/have line
func ParseCapabilities(line string) (string, string) {
	parts := bytes.SplitN([]byte(line), []byte{0}, 2)
	if len(parts) == 1 {
		return string(parts[0]), ""
	}
	return string(parts[0]), string(parts[1])
}
