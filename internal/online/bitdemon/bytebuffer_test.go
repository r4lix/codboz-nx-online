package bitdemon

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestTypeCheckedByteBufferGoldenAndRoundTrip(t *testing.T) {
	writer := NewByteWriter(true)
	writer.WriteUint8(0x7f)
	writer.WriteInt32(-1234567)
	writer.WriteUint32(0x12345678)
	writer.WriteUint64(0x0102030405060708)
	if err := writer.WriteString("BOZ"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := writer.WriteBlob([]byte{0xaa, 0xbb, 0xcc}); err != nil {
		t.Fatalf("WriteBlob() error = %v", err)
	}

	want := []byte{
		0x03, 0x7f,
		0x07, 0x79, 0x29, 0xed, 0xff,
		0x08, 0x78, 0x56, 0x34, 0x12,
		0x0a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x10, 'B', 'O', 'Z', 0x00,
		0x13, 0x08, 0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc,
	}
	encoded := writer.Bytes()
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded byte buffer = %x, want %x", encoded, want)
	}

	reader := NewByteReader(encoded, true)
	assertReadUint8(t, reader, 0x7f)
	if got, err := reader.ReadInt32(); err != nil || got != -1234567 {
		t.Fatalf("ReadInt32() = %d, %v, want -1234567, nil", got, err)
	}
	assertReadUint32(t, reader, 0x12345678)
	assertReadUint64(t, reader, 0x0102030405060708)
	if got, err := reader.ReadString(3); err != nil || got != "BOZ" {
		t.Fatalf("ReadString() = %q, %v, want BOZ, nil", got, err)
	}
	if got, err := reader.ReadBlob(3); err != nil || !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("ReadBlob() = %x, %v, want aabbcc, nil", got, err)
	}
	if reader.Remaining() != 0 {
		t.Fatalf("Remaining() = %d, want 0", reader.Remaining())
	}
}

func TestUntypedByteBufferOmitsAllTypeTags(t *testing.T) {
	writer := NewByteWriter(false)
	writer.WriteUint32(0x12345678)
	if err := writer.WriteBlob([]byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("WriteBlob() error = %v", err)
	}
	want := []byte{0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb}
	if got := writer.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("encoded untyped byte buffer = %x, want %x", got, want)
	}

	reader := NewByteReader(want, false)
	assertReadUint32(t, reader, 0x12345678)
	if got, err := reader.ReadBlob(2); err != nil || !bytes.Equal(got, []byte{0xaa, 0xbb}) {
		t.Fatalf("ReadBlob() = %x, %v, want aabb, nil", got, err)
	}
}

func TestByteReaderErrorsAreAtomic(t *testing.T) {
	reader := NewByteReader([]byte{byte(TypeUint8), 0x34}, true)
	if _, err := reader.ReadUint32(); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("ReadUint32() error = %v, want ErrUnexpectedType", err)
	}
	if reader.offset != 0 {
		t.Fatalf("offset after type error = %d, want 0", reader.offset)
	}
	reader = NewByteReader([]byte{byte(TypeUint32), 0x34}, true)
	if _, err := reader.ReadUint32(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadUint32() error = %v, want io.ErrUnexpectedEOF", err)
	}
	if reader.offset != 0 {
		t.Fatalf("offset after truncated value = %d, want 0", reader.offset)
	}
}

func TestByteReaderRejectsInvalidVariableLengthValues(t *testing.T) {
	stringReader := NewByteReader([]byte{byte(TypeString), 'B', 'O', 'Z'}, true)
	if _, err := stringReader.ReadString(3); !errors.Is(err, ErrMissingNUL) {
		t.Fatalf("ReadString() error = %v, want ErrMissingNUL", err)
	}

	blob := []byte{byte(TypeBlob), byte(TypeUint32), 0x03, 0x00, 0x00, 0x00, 1, 2, 3}
	blobReader := NewByteReader(blob, true)
	if _, err := blobReader.ReadBlob(2); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("ReadBlob() error = %v, want ErrValueTooLarge", err)
	}
	if blobReader.offset != 0 {
		t.Fatalf("offset after oversized blob = %d, want 0", blobReader.offset)
	}
}

func TestByteWriterRejectsEmbeddedNULAndReturnsCopies(t *testing.T) {
	writer := NewByteWriter(true)
	if err := writer.WriteString("BOZ\x00ignored"); !errors.Is(err, ErrEmbeddedNUL) {
		t.Fatalf("WriteString() error = %v, want ErrEmbeddedNUL", err)
	}
	writer.WriteUint8(7)
	first := writer.Bytes()
	first[0] = 0xff
	if got := writer.Bytes(); got[0] != byte(TypeUint8) {
		t.Fatalf("Bytes() exposed mutable storage: got %x", got)
	}
}

func assertReadUint8(t *testing.T, reader *ByteReader, want uint8) {
	t.Helper()
	got, err := reader.ReadUint8()
	if err != nil || got != want {
		t.Fatalf("ReadUint8() = %x, %v, want %x, nil", got, err, want)
	}
}

func assertReadUint32(t *testing.T, reader *ByteReader, want uint32) {
	t.Helper()
	got, err := reader.ReadUint32()
	if err != nil || got != want {
		t.Fatalf("ReadUint32() = %x, %v, want %x, nil", got, err, want)
	}
}

func assertReadUint64(t *testing.T, reader *ByteReader, want uint64) {
	t.Helper()
	got, err := reader.ReadUint64()
	if err != nil || got != want {
		t.Fatalf("ReadUint64() = %x, %v, want %x, nil", got, err, want)
	}
}
