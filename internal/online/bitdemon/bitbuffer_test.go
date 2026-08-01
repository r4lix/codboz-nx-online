package bitdemon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func TestBitReaderObservedBOZAuthHeader(t *testing.T) {
	payload := mustDecodeBitHex(t, "514f34c6392240020000000000000000000028fa50401316")
	reader := NewBitReader(payload)

	typeChecked, err := reader.ReadTypeCheckedFlag()
	if err != nil {
		t.Fatal(err)
	}
	if !typeChecked {
		t.Fatal("type-checked flag = false, want true")
	}
	seed, err := reader.ReadUint32()
	if err != nil {
		t.Fatal(err)
	}
	if seed != 0xe718d13d {
		t.Fatalf("IV seed = 0x%08x, want 0xe718d13d", seed)
	}
	titleID, err := reader.ReadUint32()
	if err != nil {
		t.Fatal(err)
	}
	if titleID != 18436 {
		t.Fatalf("title ID = %d, want 18436", titleID)
	}
	if reader.bitOffset != 75 {
		t.Fatalf("bit offset = %d, want 75", reader.bitOffset)
	}
}

func TestBitWriterMatchesObservedBOZAuthHeader(t *testing.T) {
	writer := NewBitWriter(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(0xe718d13d)
	writer.WriteUint32(18436)

	want := mustDecodeBitHex(t, "514f34c6392240020000")
	if got := writer.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("encoded header = %x, want %x", got, want)
	}
	if writer.bitOffset != 75 {
		t.Fatalf("bit length = %d, want 75", writer.bitOffset)
	}
}

func TestBitBufferRoundTripsUsedPrimitivesAndRawBytes(t *testing.T) {
	writer := NewBitWriter(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(0x89abcdef)
	writer.SetTypeChecked(false)
	writer.WriteRaw([]byte{0xde, 0xad, 0xbe, 0xef})

	reader := NewBitReader(writer.Bytes())
	if checked, err := reader.ReadTypeCheckedFlag(); err != nil || !checked {
		t.Fatalf("ReadTypeCheckedFlag() = %t, %v", checked, err)
	}
	if value, err := reader.ReadUint32(); err != nil || value != 0x89abcdef {
		t.Fatalf("ReadUint32() = 0x%08x, %v", value, err)
	}
	reader.SetTypeChecked(false)
	if value, err := reader.ReadRaw(4); err != nil || !bytes.Equal(value, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("ReadRaw() = %x, %v", value, err)
	}
}

func TestBitReaderRollsBackAfterTypeMismatchOrTruncation(t *testing.T) {
	writer := NewBitWriter(true)
	writer.WriteUint32(42)
	reader := NewBitReader(writer.Bytes())
	reader.SetTypeChecked(true)

	if _, err := reader.ReadUint64(); !errors.Is(err, ErrUnexpectedType) {
		t.Fatalf("ReadUint64() error = %v, want %v", err, ErrUnexpectedType)
	}
	if reader.bitOffset != 0 {
		t.Fatalf("offset after type mismatch = %d, want 0", reader.bitOffset)
	}
	if value, err := reader.ReadUint32(); err != nil || value != 42 {
		t.Fatalf("ReadUint32() = %d, %v", value, err)
	}
	start := reader.bitOffset
	if _, err := reader.ReadRaw(1); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadRaw() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if reader.bitOffset != start {
		t.Fatalf("offset after truncation = %d, want %d", reader.bitOffset, start)
	}
}

func TestBitWriterBytesReturnsCopy(t *testing.T) {
	writer := NewBitWriter(false)
	writer.WriteUint8(0xa5)
	encoded := writer.Bytes()
	encoded[0] = 0
	if got := writer.Bytes()[0]; got != 0xa5 {
		t.Fatalf("writer data changed through returned slice: 0x%02x", got)
	}
}

func FuzzBitReaderDoesNotPanic(f *testing.F) {
	f.Add(mustDecodeBitHex(f, "514f34c6392240020000"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		reader := NewBitReader(payload)
		_, _ = reader.ReadTypeCheckedFlag()
		_, _ = reader.ReadUint32()
		_, _ = reader.ReadUint64()
	})
}

type bitTestingTB interface {
	Helper()
	Fatalf(string, ...any)
}

func mustDecodeBitHex(tb bitTestingTB, value string) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		tb.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}
