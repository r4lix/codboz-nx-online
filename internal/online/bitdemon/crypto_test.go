package bitdemon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestTruncatedHMACSHA1RFC2202Vector(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	got := TruncatedHMACSHA1(key, []byte("Hi There"))
	want := [4]byte{0xb6, 0x17, 0x31, 0x86}
	if got != want {
		t.Fatalf("TruncatedHMACSHA1() = %x, want %x", got, want)
	}
}

func TestDeriveIVUsesTigerOfLittleEndianCounter(t *testing.T) {
	tests := []struct {
		counter uint32
		iv      [8]byte
	}{
		{counter: 0, iv: [8]byte{0x60, 0x5d, 0x1b, 0x8c, 0x13, 0x2b, 0xf5, 0xd1}},
		{counter: 1, iv: [8]byte{0xcd, 0x30, 0x53, 0x16, 0xb8, 0xf4, 0xa5, 0x16}},
		{counter: 2, iv: [8]byte{0x90, 0x45, 0x6c, 0xd7, 0x98, 0x79, 0x17, 0x8b}},
		{counter: 255, iv: [8]byte{0x83, 0x67, 0x89, 0xcd, 0x73, 0xf1, 0x5b, 0xb8}},
		{counter: 256, iv: [8]byte{0xc9, 0xf4, 0x27, 0x3f, 0x68, 0xf2, 0xb4, 0xe9}},
	}

	for _, test := range tests {
		got := DeriveIV(test.counter)
		if got != test.iv {
			t.Fatalf("DeriveIV(%d) = %x, want %x", test.counter, got, test.iv)
		}
	}
}

func TestTripleDESCBCVectorAndRoundTrip(t *testing.T) {
	key := mustDecodeHex(t, "0123456789abcdeffedcba98765432100011223344556677")
	ivBytes := mustDecodeHex(t, "1234567890abcdef")
	var iv [8]byte
	copy(iv[:], ivBytes)
	plaintext := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")
	wantCiphertext := mustDecodeHex(t, "3bd0249d89b5667613c074710acf02b2")

	ciphertext, err := Encrypt3DESCBC(key, iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3DESCBC() error = %v", err)
	}
	if !bytes.Equal(ciphertext, wantCiphertext) {
		t.Fatalf("Encrypt3DESCBC() = %x, want %x", ciphertext, wantCiphertext)
	}
	decrypted, err := Decrypt3DESCBC(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt3DESCBC() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt3DESCBC() = %x, want %x", decrypted, plaintext)
	}
}

func TestTripleDESCBCValidatesKeyAndBlockLength(t *testing.T) {
	var iv [8]byte
	if _, err := Encrypt3DESCBC(make([]byte, 23), iv, make([]byte, 8)); !errors.Is(err, ErrInvalidSessionKey) {
		t.Fatalf("Encrypt3DESCBC() key error = %v, want ErrInvalidSessionKey", err)
	}
	if _, err := Encrypt3DESCBC(make([]byte, 24), iv, make([]byte, 7)); !errors.Is(err, ErrInvalidBlockLength) {
		t.Fatalf("Encrypt3DESCBC() length error = %v, want ErrInvalidBlockLength", err)
	}
}

func TestPadTo3DESBlock(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := PadTo3DESBlock(payload)
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("PadTo3DESBlock() = %x, want %x", got, want)
	}
	got[0] = 0xff
	if payload[0] != 1 {
		t.Fatal("PadTo3DESBlock() returned storage aliasing its input")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return decoded
}
