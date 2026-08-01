package bitdemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTripWithPartialIO(t *testing.T) {
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	writer := &shortWriter{maximum: 2}
	if err := WriteFrame(writer, body); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	wantFrame := []byte{0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(writer.data, wantFrame) {
		t.Fatalf("WriteFrame() = %x, want %x", writer.data, wantFrame)
	}

	record, err := ReadTransportRecord(&shortReader{data: writer.data, maximum: 2}, 64)
	if err != nil {
		t.Fatalf("ReadTransportRecord() error = %v", err)
	}
	if record.Kind != RecordKindFrame || !bytes.Equal(record.Body, body) {
		t.Fatalf("ReadTransportRecord() = %#v, want frame %x", record, body)
	}
}

func TestFrameKeepalive(t *testing.T) {
	frame := []byte{0, 0, 0, 0}
	record, err := ReadTransportRecord(bytes.NewReader(frame), 1)
	if err != nil {
		t.Fatalf("ReadTransportRecord() error = %v", err)
	}
	if record.Kind != RecordKindKeepalive || len(record.Body) != LobbyKeepaliveBodyLen {
		t.Fatalf("ReadTransportRecord() = %#v, want keepalive", record)
	}
}

func TestBufferAvailableRecordDoesNotDesynchronizeNextFrame(t *testing.T) {
	writer := &shortWriter{maximum: 1}
	if err := WriteBufferAvailableRecord(writer, 0x10000); err != nil {
		t.Fatalf("WriteBufferAvailableRecord() error = %v", err)
	}
	if err := WriteFrame(writer, []byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	wantPrefix := []byte{0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	if !bytes.Equal(writer.data[:8], wantPrefix) {
		t.Fatalf("buffer-available encoding = %x, want %x", writer.data[:8], wantPrefix)
	}

	reader := &shortReader{data: writer.data, maximum: 1}
	record, err := ReadTransportRecord(reader, 64)
	if err != nil {
		t.Fatalf("first ReadTransportRecord() error = %v", err)
	}
	if record.Kind != RecordKindBufferAvailable || record.AvailableBuffer != 0x10000 || record.Body != nil {
		t.Fatalf("first ReadTransportRecord() = %#v, want buffer-available 65536", record)
	}

	record, err = ReadTransportRecord(reader, 64)
	if err != nil {
		t.Fatalf("second ReadTransportRecord() error = %v", err)
	}
	if record.Kind != RecordKindFrame || !bytes.Equal(record.Body, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("second ReadTransportRecord() = %#v, want frame 010203", record)
	}
}

func TestFrameRejectsReservedBodySize(t *testing.T) {
	body := make([]byte, BufferAvailableRecordMarker)
	if err := WriteFrame(io.Discard, body); !errors.Is(err, ErrReservedFrameBodySize) {
		t.Fatalf("WriteFrame() error = %v, want ErrReservedFrameBodySize", err)
	}
	if _, err := MarshalFrame(body); !errors.Is(err, ErrReservedFrameBodySize) {
		t.Fatalf("MarshalFrame() error = %v, want ErrReservedFrameBodySize", err)
	}
}

func TestReadTransportRecordRejectsOversizedBodyBeforeReadingIt(t *testing.T) {
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], 65)
	_, err := ReadTransportRecord(bytes.NewReader(prefix[:]), 64)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadTransportRecord() error = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadTransportRecordRejectsTruncatedBody(t *testing.T) {
	_, err := ReadTransportRecord(bytes.NewReader([]byte{2, 0, 0, 0, 1}), 64)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadTransportRecord() error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadTransportRecordRejectsTruncatedBufferAvailableValue(t *testing.T) {
	_, err := ReadTransportRecord(bytes.NewReader([]byte{0xc8, 0, 0, 0, 1}), 64)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadTransportRecord() error = %v, want io.ErrUnexpectedEOF", err)
	}
}

type shortWriter struct {
	data    []byte
	maximum int
}

func (writer *shortWriter) Write(data []byte) (int, error) {
	length := min(len(data), writer.maximum)
	writer.data = append(writer.data, data[:length]...)
	return length, nil
}

type shortReader struct {
	data    []byte
	offset  int
	maximum int
}

func (reader *shortReader) Read(destination []byte) (int, error) {
	if reader.offset == len(reader.data) {
		return 0, io.EOF
	}
	length := min(len(destination), reader.maximum, len(reader.data)-reader.offset)
	copy(destination, reader.data[reader.offset:reader.offset+length])
	reader.offset += length
	return length, nil
}
