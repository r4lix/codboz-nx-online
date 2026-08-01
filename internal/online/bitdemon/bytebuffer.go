package bitdemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

type DataType byte

const (
	TypeUint8  DataType = 0x03
	TypeInt32  DataType = 0x07
	TypeUint32 DataType = 0x08
	TypeUint64 DataType = 0x0a
	TypeString DataType = 0x10
	TypeBlob   DataType = 0x13
)

var (
	ErrEmbeddedNUL    = errors.New("bitdemon string contains an embedded NUL")
	ErrMissingNUL     = errors.New("bitdemon string is not NUL-terminated")
	ErrUnexpectedType = errors.New("unexpected bitdemon data type")
	ErrValueTooLarge  = errors.New("bitdemon value is too large")
)

type TypeError struct {
	Expected DataType
	Actual   DataType
}

func (err *TypeError) Error() string {
	return fmt.Sprintf("%v: expected 0x%02x, received 0x%02x", ErrUnexpectedType, byte(err.Expected), byte(err.Actual))
}

func (err *TypeError) Unwrap() error {
	return ErrUnexpectedType
}

type ByteWriter struct {
	typeChecked bool
	data        []byte
}

func NewByteWriter(typeChecked bool) *ByteWriter {
	return &ByteWriter{typeChecked: typeChecked}
}

func (writer *ByteWriter) Bytes() []byte {
	return bytes.Clone(writer.data)
}

func (writer *ByteWriter) WriteRaw(value []byte) {
	writer.data = append(writer.data, value...)
}

func (writer *ByteWriter) WriteUint8(value uint8) {
	writer.writeType(TypeUint8)
	writer.data = append(writer.data, value)
}

func (writer *ByteWriter) WriteInt32(value int32) {
	writer.writeType(TypeInt32)
	writer.data = binary.LittleEndian.AppendUint32(writer.data, uint32(value))
}

func (writer *ByteWriter) WriteUint32(value uint32) {
	writer.writeType(TypeUint32)
	writer.data = binary.LittleEndian.AppendUint32(writer.data, value)
}

func (writer *ByteWriter) WriteUint64(value uint64) {
	writer.writeType(TypeUint64)
	writer.data = binary.LittleEndian.AppendUint64(writer.data, value)
}

func (writer *ByteWriter) WriteString(value string) error {
	if strings.IndexByte(value, 0) >= 0 {
		return ErrEmbeddedNUL
	}
	if uint64(len(value))+1 > math.MaxUint32 {
		return fmt.Errorf("%w: string length %d", ErrValueTooLarge, len(value))
	}
	writer.writeType(TypeString)
	writer.data = append(writer.data, value...)
	writer.data = append(writer.data, 0)
	return nil
}

func (writer *ByteWriter) WriteBlob(value []byte) error {
	if uint64(len(value)) > math.MaxUint32 {
		return fmt.Errorf("%w: blob length %d", ErrValueTooLarge, len(value))
	}
	writer.writeType(TypeBlob)
	writer.WriteUint32(uint32(len(value)))
	writer.data = append(writer.data, value...)
	return nil
}

func (writer *ByteWriter) writeType(dataType DataType) {
	if writer.typeChecked {
		writer.data = append(writer.data, byte(dataType))
	}
}

type ByteReader struct {
	typeChecked bool
	data        []byte
	offset      int
}

func NewByteReader(data []byte, typeChecked bool) *ByteReader {
	return &ByteReader{data: data, typeChecked: typeChecked}
}

func (reader *ByteReader) Remaining() int {
	return len(reader.data) - reader.offset
}

func (reader *ByteReader) ReadRaw(length uint32) ([]byte, error) {
	start := reader.offset
	value, err := reader.read(int(length))
	if err != nil {
		reader.offset = start
		return nil, err
	}
	return bytes.Clone(value), nil
}

func (reader *ByteReader) ReadUint8() (uint8, error) {
	start := reader.offset
	if err := reader.expect(TypeUint8); err != nil {
		reader.offset = start
		return 0, err
	}
	data, err := reader.read(1)
	if err != nil {
		reader.offset = start
		return 0, err
	}
	return data[0], nil
}

func (reader *ByteReader) ReadInt32() (int32, error) {
	start := reader.offset
	if err := reader.expect(TypeInt32); err != nil {
		reader.offset = start
		return 0, err
	}
	data, err := reader.read(4)
	if err != nil {
		reader.offset = start
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

func (reader *ByteReader) ReadUint32() (uint32, error) {
	start := reader.offset
	if err := reader.expect(TypeUint32); err != nil {
		reader.offset = start
		return 0, err
	}
	data, err := reader.read(4)
	if err != nil {
		reader.offset = start
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (reader *ByteReader) ReadUint64() (uint64, error) {
	start := reader.offset
	if err := reader.expect(TypeUint64); err != nil {
		reader.offset = start
		return 0, err
	}
	data, err := reader.read(8)
	if err != nil {
		reader.offset = start
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (reader *ByteReader) ReadString(maxLength uint32) (string, error) {
	start := reader.offset
	if err := reader.expect(TypeString); err != nil {
		reader.offset = start
		return "", err
	}

	remainder := reader.data[reader.offset:]
	terminator := bytes.IndexByte(remainder, 0)
	if terminator < 0 {
		reader.offset = start
		return "", ErrMissingNUL
	}
	if uint64(terminator) > uint64(maxLength) {
		reader.offset = start
		return "", fmt.Errorf("%w: string length %d exceeds %d", ErrValueTooLarge, terminator, maxLength)
	}
	reader.offset += terminator + 1
	return string(remainder[:terminator]), nil
}

func (reader *ByteReader) ReadBlob(maxLength uint32) ([]byte, error) {
	start := reader.offset
	if err := reader.expect(TypeBlob); err != nil {
		reader.offset = start
		return nil, err
	}
	length, err := reader.ReadUint32()
	if err != nil {
		reader.offset = start
		return nil, err
	}
	if length > maxLength {
		reader.offset = start
		return nil, fmt.Errorf("%w: blob length %d exceeds %d", ErrValueTooLarge, length, maxLength)
	}
	value, err := reader.read(int(length))
	if err != nil {
		reader.offset = start
		return nil, err
	}
	return bytes.Clone(value), nil
}

func (reader *ByteReader) expect(expected DataType) error {
	if !reader.typeChecked {
		return nil
	}
	data, err := reader.read(1)
	if err != nil {
		return err
	}
	actual := DataType(data[0])
	if actual != expected {
		return &TypeError{Expected: expected, Actual: actual}
	}
	return nil
}

func (reader *ByteReader) read(length int) ([]byte, error) {
	if length < 0 || length > reader.Remaining() {
		return nil, io.ErrUnexpectedEOF
	}
	start := reader.offset
	reader.offset += length
	return reader.data[start:reader.offset], nil
}
