package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	MaxPktSize       = 65516
	PktLenSize       = 4
	FlushPkt         = "0000"
	SideBandMain     = 1
	SideBandProgress = 2
	SideBandError    = 3
)

var (
	ErrPacketTooLarge = errors.New("packet exceeds maximum allowed size")
	ErrInvalidPacket  = errors.New("invalid packet format")
	ErrEmptyPacket    = errors.New("empty packet")
)

func EncodePacketLine(data []byte) ([]byte, error) {
	if len(data) > MaxPktSize-PktLenSize {
		return nil, ErrPacketTooLarge
	}
	length := len(data) + PktLenSize
	prefix := fmt.Sprintf("%04x", length)
	result := make([]byte, PktLenSize+len(data))
	copy(result[:PktLenSize], prefix)
	copy(result[PktLenSize:], data)
	return result, nil
}

func DecodePacketLine(r io.Reader) ([]byte, bool, error) {
	prefix := make([]byte, PktLenSize)
	n, err := io.ReadFull(r, prefix)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read packet length: %w", err)
	}
	if n != PktLenSize {
		return nil, false, ErrInvalidPacket
	}
	if bytes.Equal(prefix, []byte(FlushPkt)) {
		return nil, true, nil
	}
	lengthStr := string(prefix)
	length, err := hex.DecodeString(lengthStr)
	if err != nil || len(length) != 2 {
		return nil, false, fmt.Errorf("invalid packet length: %w", err)
	}
	dataLength := (int(length[0])<<8 | int(length[1])) - PktLenSize
	if dataLength <= 0 {
		return nil, false, ErrEmptyPacket
	}
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

func WritePacketLine(w io.Writer, data []byte) error {
	encoded, err := EncodePacketLine(data)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

func ReadPacketLine(r io.Reader) ([]byte, bool, error) {
	return DecodePacketLine(r)
}

func WriteFlushPacket(w io.Writer) error {
	_, err := w.Write([]byte(FlushPkt))
	return err
}

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

func WriteAllPacketLines(w io.Writer, packets [][]byte) error {
	for _, data := range packets {
		if err := WritePacketLine(w, data); err != nil {
			return err
		}
	}
	return WriteFlushPacket(w)
}

func EncodeSideBand(channel byte, data []byte) []byte {
	result := make([]byte, len(data)+1)
	result[0] = channel
	copy(result[1:], data)
	return result
}

func DecodeSideBand(data []byte) (byte, []byte, error) {
	if len(data) < 1 {
		return 0, nil, errors.New("invalid side-band data")
	}
	return data[0], data[1:], nil
}

func WriteSideBand(w io.Writer, channel byte, data []byte) error {
	return WritePacketLine(w, EncodeSideBand(channel, data))
}

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

func WriteDelimitedPacket(w io.Writer, first string, capabilities string) error {
	data := []byte(first)
	if capabilities != "" {
		data = append(data, 0)
		data = append(data, []byte(capabilities)...)
	}
	return WritePacketLine(w, data)
}

func ParseCapabilities(line string) (string, string) {
	parts := bytes.SplitN([]byte(line), []byte{0}, 2)
	if len(parts) == 1 {
		return string(parts[0]), ""
	}
	return string(parts[0]), string(parts[1])
}
