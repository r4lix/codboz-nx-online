package bitdemon

import (
	"bytes"
	"encoding/binary"
	"io"
)

const bitModeTypeWidth = 5

// BitWriter emits the little-endian, least-significant-bit-first bit stream
// used by legacy BitDemon authentication messages.
type BitWriter struct {
	typeChecked bool
	data        []byte
	bitOffset   uint64
}

func NewBitWriter(typeChecked bool) *BitWriter {
	return &BitWriter{typeChecked: typeChecked}
}

func (writer *BitWriter) SetTypeChecked(typeChecked bool) {
	writer.typeChecked = typeChecked
}

func (writer *BitWriter) Bytes() []byte {
	return bytes.Clone(writer.data)
}

// WriteTypeCheckedFlag writes the one-bit stream prefix that tells the peer
// whether following primitive values carry five-bit type tags.
func (writer *BitWriter) WriteTypeCheckedFlag() {
	if writer.typeChecked {
		writer.writeBits([]byte{1}, 1)
		return
	}
	writer.writeBits([]byte{0}, 1)
}

func (writer *BitWriter) WriteRaw(value []byte) {
	writer.writeBits(value, uint64(len(value))*8)
}

func (writer *BitWriter) WriteUint8(value uint8) {
	writer.writeType(TypeUint8)
	writer.writeBits([]byte{value}, 8)
}

func (writer *BitWriter) WriteUint32(value uint32) {
	writer.writeType(TypeUint32)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	writer.writeBits(encoded[:], 32)
}

func (writer *BitWriter) writeType(dataType DataType) {
	if writer.typeChecked {
		writer.writeBits([]byte{byte(dataType)}, bitModeTypeWidth)
	}
}

func (writer *BitWriter) writeBits(value []byte, count uint64) {
	for bit := uint64(0); bit < count; bit++ {
		outputBit := writer.bitOffset + bit
		outputByte := outputBit / 8
		if outputByte == uint64(len(writer.data)) {
			writer.data = append(writer.data, 0)
		}
		if value[int(bit/8)]&(1<<uint(bit%8)) != 0 {
			writer.data[int(outputByte)] |= 1 << uint(outputBit%8)
		}
	}
	writer.bitOffset += count
}

// BitReader consumes the little-endian, least-significant-bit-first bit
// stream used by legacy BitDemon authentication messages.
type BitReader struct {
	typeChecked bool
	data        []byte
	bitOffset   uint64
}

func NewBitReader(data []byte) *BitReader {
	return &BitReader{data: data}
}

func (reader *BitReader) SetTypeChecked(typeChecked bool) {
	reader.typeChecked = typeChecked
}

func (reader *BitReader) RemainingBits() uint64 {
	return uint64(len(reader.data))*8 - reader.bitOffset
}

// ReadTypeCheckedFlag reads the one-bit stream prefix and applies it to
// subsequent primitive reads.
func (reader *BitReader) ReadTypeCheckedFlag() (bool, error) {
	value, err := reader.readBits(1)
	if err != nil {
		return false, err
	}
	reader.typeChecked = value[0]&1 != 0
	return reader.typeChecked, nil
}

func (reader *BitReader) ReadRaw(length uint32) ([]byte, error) {
	requiredBits := uint64(length) * 8
	if requiredBits > reader.RemainingBits() {
		return nil, io.ErrUnexpectedEOF
	}
	return reader.readBits(requiredBits)
}

func (reader *BitReader) ReadUint32() (uint32, error) {
	start := reader.bitOffset
	if err := reader.expect(TypeUint32); err != nil {
		reader.bitOffset = start
		return 0, err
	}
	value, err := reader.readBits(32)
	if err != nil {
		reader.bitOffset = start
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}

func (reader *BitReader) ReadUint64() (uint64, error) {
	start := reader.bitOffset
	if err := reader.expect(TypeUint64); err != nil {
		reader.bitOffset = start
		return 0, err
	}
	value, err := reader.readBits(64)
	if err != nil {
		reader.bitOffset = start
		return 0, err
	}
	return binary.LittleEndian.Uint64(value), nil
}

func (reader *BitReader) expect(expected DataType) error {
	if !reader.typeChecked {
		return nil
	}
	encoded, err := reader.readBits(bitModeTypeWidth)
	if err != nil {
		return err
	}
	actual := DataType(encoded[0])
	if actual != expected {
		return &TypeError{Expected: expected, Actual: actual}
	}
	return nil
}

func (reader *BitReader) readBits(count uint64) ([]byte, error) {
	if count > reader.RemainingBits() {
		return nil, io.ErrUnexpectedEOF
	}
	resultBytes := count / 8
	if count%8 != 0 {
		resultBytes++
	}
	result := make([]byte, int(resultBytes))
	for bit := uint64(0); bit < count; bit++ {
		inputBit := reader.bitOffset + bit
		if reader.data[int(inputBit/8)]&(1<<uint(inputBit%8)) != 0 {
			result[int(bit/8)] |= 1 << uint(bit%8)
		}
	}
	reader.bitOffset += count
	return result, nil
}
