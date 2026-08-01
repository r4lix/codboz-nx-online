package bitdemon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	FramePrefixSize             = 4
	DefaultMaxFrameBody         = 1 << 20
	LobbyKeepaliveBodyLen       = 0
	BufferAvailableRecordMarker = 200
)

var (
	ErrFrameTooLarge         = errors.New("bitdemon frame body is too large")
	ErrReservedFrameBodySize = errors.New("bitdemon frame body uses a reserved size")
)

type TransportRecordKind uint8

const (
	RecordKindFrame TransportRecordKind = iota + 1
	RecordKindKeepalive
	RecordKindBufferAvailable
)

type TransportRecord struct {
	Kind            TransportRecordKind
	Body            []byte
	AvailableBuffer uint32
}

func ReadTransportRecord(reader io.Reader, maxBodySize uint32) (TransportRecord, error) {
	if maxBodySize == 0 {
		maxBodySize = DefaultMaxFrameBody
	}

	var prefix [FramePrefixSize]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return TransportRecord{}, fmt.Errorf("read bitdemon transport prefix: %w", err)
	}

	bodySize := binary.LittleEndian.Uint32(prefix[:])
	if bodySize == LobbyKeepaliveBodyLen {
		return TransportRecord{Kind: RecordKindKeepalive}, nil
	}
	if bodySize == BufferAvailableRecordMarker {
		var value [4]byte
		if _, err := io.ReadFull(reader, value[:]); err != nil {
			return TransportRecord{}, fmt.Errorf("read bitdemon buffer-available value: %w", err)
		}
		return TransportRecord{
			Kind:            RecordKindBufferAvailable,
			AvailableBuffer: binary.LittleEndian.Uint32(value[:]),
		}, nil
	}
	if bodySize > maxBodySize {
		return TransportRecord{}, fmt.Errorf("%w: %d exceeds %d", ErrFrameTooLarge, bodySize, maxBodySize)
	}
	if uint64(bodySize) > uint64(^uint(0)>>1) {
		return TransportRecord{}, fmt.Errorf("%w: %d exceeds platform allocation limit", ErrFrameTooLarge, bodySize)
	}

	body := make([]byte, int(bodySize))
	if _, err := io.ReadFull(reader, body); err != nil {
		return TransportRecord{}, fmt.Errorf("read bitdemon frame body: %w", err)
	}
	return TransportRecord{Kind: RecordKindFrame, Body: body}, nil
}

func WriteFrame(writer io.Writer, body []byte) error {
	if uint64(len(body)) > math.MaxUint32 {
		return fmt.Errorf("%w: %d exceeds %d", ErrFrameTooLarge, len(body), uint64(math.MaxUint32))
	}
	if len(body) == BufferAvailableRecordMarker {
		return fmt.Errorf("%w: %d is the buffer-available marker", ErrReservedFrameBodySize, len(body))
	}

	var prefix [FramePrefixSize]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(body)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return fmt.Errorf("write bitdemon frame prefix: %w", err)
	}
	if err := writeAll(writer, body); err != nil {
		return fmt.Errorf("write bitdemon frame body: %w", err)
	}
	return nil
}

func MarshalFrame(body []byte) ([]byte, error) {
	if uint64(len(body)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d exceeds %d", ErrFrameTooLarge, len(body), uint64(math.MaxUint32))
	}
	if len(body) == BufferAvailableRecordMarker {
		return nil, fmt.Errorf("%w: %d is the buffer-available marker", ErrReservedFrameBodySize, len(body))
	}

	frame := make([]byte, FramePrefixSize+len(body))
	binary.LittleEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[FramePrefixSize:], body)
	return frame, nil
}

func WriteBufferAvailableRecord(writer io.Writer, availableBuffer uint32) error {
	var record [8]byte
	binary.LittleEndian.PutUint32(record[0:4], BufferAvailableRecordMarker)
	binary.LittleEndian.PutUint32(record[4:8], availableBuffer)
	if err := writeAll(writer, record[:]); err != nil {
		return fmt.Errorf("write bitdemon buffer-available record: %w", err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written < 1 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
