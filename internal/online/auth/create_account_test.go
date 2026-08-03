package auth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

func TestParseCreateAccountBody(t *testing.T) {
	passwordHash := bitdemon.Tiger192([]byte("GEN__fixture"))
	body := makeCreateAccountBody(t, 0xe718d13d, "GEN__fixture", passwordHash)

	request, err := ParseCreateAccountBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if request.IVSeed != 0xe718d13d || request.TitleID != BOZTitleID || request.LicenseHash != 0 {
		t.Fatalf("request header = %#v", request)
	}
	if request.Username != "GEN__fixture" {
		t.Fatalf("username = %q, want %q", request.Username, "GEN__fixture")
	}
	if request.PasswordHash != passwordHash {
		t.Fatalf("password hash = %x, want %x", request.PasswordHash, passwordHash)
	}
}

func TestParseCreateAccountBodyFixedKnownAnswer(t *testing.T) {
	// Sanitized fixed vector independently packed and encrypted with OpenSSL.
	body, err := hex.DecodeString("0000514f34c63922400200000000000000000028fa504013160a668a606b1173ee5f10d0c81b83b0bd994d89606b1173ee5f10d0c81b83b0bd994d89606b1173ee5f10d0c81b83b0bd994d89606b1173ee5f10f822a91e9ded03d03cffc29f36e8a094920be86f58ca7a88475833eca099b9ab00")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ParseCreateAccountBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if request.IVSeed != 0xe718d13d || request.TitleID != BOZTitleID || request.Username != "GEN__fixture" {
		t.Fatalf("request = %#v", request)
	}
	for index, value := range request.PasswordHash {
		if value != byte(index) {
			t.Fatalf("password hash byte %d = 0x%02x, want 0x%02x", index, value, byte(index))
		}
	}
}

func TestMarshalCreateAccountReplyBody(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		want   []byte
	}{
		{name: "created", status: StatusNoError, want: []byte{0, 0x01, 0x11, 0xaf, 0, 0, 0}},
		{name: "already exists", status: StatusCreateUsernameExists, want: []byte{0, 0x01, 0xd1, 0xb0, 0, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := MarshalCreateAccountReplyBody(test.status)
			if !bytes.Equal(body, test.want) {
				t.Fatalf("body = %x, want %x", body, test.want)
			}
		})
	}
}

func TestParseCreateAccountBodyRejectsInvalidEnvelope(t *testing.T) {
	valid := makeCreateAccountBody(t, 0x12345678, "GEN__fixture", bitdemon.Tiger192([]byte("fixture")))
	tests := []struct {
		name string
		body func() []byte
		want error
	}{
		{name: "short", body: func() []byte { return append([]byte(nil), valid[:len(valid)-1]...) }, want: ErrMalformedMessage},
		{name: "encrypted", body: func() []byte { return replaceByte(valid, 0, 1) }, want: ErrEncryptedCreateAccount},
		{name: "wrong message", body: func() []byte { return replaceByte(valid, 1, 0x0a) }, want: ErrUnexpectedMessageType},
		{name: "no type checking", body: func() []byte { return replaceByte(valid, 2, valid[2]&^1) }, want: ErrTypeCheckingRequired},
		{name: "bad padding", body: func() []byte { return replaceByte(valid, len(valid)-1, valid[len(valid)-1]|0x80) }, want: ErrMalformedMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCreateAccountBody(test.body())
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseCreateAccountBody() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseCreateAccountBodyRejectsInvalidAccountBlock(t *testing.T) {
	passwordHash := bitdemon.Tiger192([]byte("fixture"))
	valid := makeCreateAccountBody(t, 0x12345678, "GEN__fixture", passwordHash)

	wrongTitle := append([]byte(nil), valid...)
	setPackedBits(wrongTitle[2:], 43, uint64(BOZTitleID+1), 32)
	if _, err := ParseCreateAccountBody(wrongTitle); !errors.Is(err, ErrUnexpectedTitle) {
		t.Fatalf("wrong title error = %v", err)
	}

	badCiphertext := append([]byte(nil), valid...)
	badCiphertext[20] ^= 0x80
	if _, err := ParseCreateAccountBody(badCiphertext); !errors.Is(err, ErrInvalidAccountBlock) {
		t.Fatalf("bad account block error = %v", err)
	}
}

func makeCreateAccountBody(t *testing.T, seed uint32, username string, passwordHash [accountPasswordSize]byte) []byte {
	t.Helper()
	if len(username) > accountUsernameSize {
		t.Fatal("test username is too long")
	}
	plaintext := make([]byte, createAccountBlockSize)
	binary.LittleEndian.PutUint32(plaintext[0:4], accountBlockSignature)
	copy(plaintext[4:68], username)
	copy(plaintext[68:92], passwordHash[:])
	ciphertext, err := bitdemon.Encrypt3DESCBC(createAccountKey[:], bitdemon.DeriveIV(seed), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	writer := bitdemon.NewBitWriter(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(seed)
	writer.WriteUint32(BOZTitleID)
	writer.SetTypeChecked(false)
	writer.WriteRaw(make([]byte, 8))
	writer.WriteRaw(ciphertext)
	body := append([]byte{0, MessageCreateAccountRequest}, writer.Bytes()...)
	if len(body) != createAccountBodySize {
		t.Fatalf("test body size = %d, want %d", len(body), createAccountBodySize)
	}
	return body
}

func replaceByte(value []byte, offset int, replacement byte) []byte {
	result := append([]byte(nil), value...)
	result[offset] = replacement
	return result
}

func setPackedBits(value []byte, offset int, replacement uint64, count int) {
	for bit := 0; bit < count; bit++ {
		mask := byte(1 << uint((offset+bit)%8))
		if replacement&(1<<uint(bit)) != 0 {
			value[(offset+bit)/8] |= mask
		} else {
			value[(offset+bit)/8] &^= mask
		}
	}
}
