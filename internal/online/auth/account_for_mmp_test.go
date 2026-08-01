package auth

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestParseAccountForMMPFixedRequest(t *testing.T) {
	body := []byte{
		0x00, 0x0a, 0x11, 0x9e, 0x15, 0x8d, 0x04, 0x22, 0x40, 0x02,
		0x00, 0x78, 0x6f, 0x5e, 0x4d, 0x3c, 0x2b, 0x1a, 0x09, 0x00,
	}
	request, err := ParseAccountForMMPBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if request.IVSeed != 0x12345678 || request.TitleID != BOZTitleID || request.AccountHash != 0x0123456789abcdef {
		t.Fatalf("request = %#v", request)
	}
}

func TestMarshalAccountForMMPSuccessBody(t *testing.T) {
	account := Account{
		UserID:      42,
		Username:    "GEN__fixture",
		AccountHash: BOZAccountHash("GEN__fixture"),
	}
	for index := range account.PasswordHash {
		account.PasswordHash[index] = byte(0x80 + index)
	}
	var sessionKey [bitdemon.SessionKeySize]byte
	for index := range sessionKey {
		sessionKey[index] = byte(index)
	}
	issuedAt := time.Unix(1_800_000_000, 0)
	expiresAt := issuedAt.Add(time.Hour)
	body, err := marshalAccountForMMPSuccessBody(account, 0x12345678, sessionKey, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 140 {
		t.Fatalf("body length = %d, want 140", len(body))
	}
	if wantPrefix := []byte{0x00, 0x0b, 0x11, 0xaf, 0, 0, 0, 0xc2, 0xb3, 0xa2, 0x91}; !bytes.Equal(body[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("body prefix = %x, want %x", body[:len(wantPrefix)], wantPrefix)
	}
	frame, err := bitdemon.MarshalFrame(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:4], []byte{0x8c, 0, 0, 0}) {
		t.Fatalf("frame prefix = %x, want 8c000000", frame[:4])
	}

	reader := bitdemon.NewBitReader(body[2:])
	if checked, err := reader.ReadTypeCheckedFlag(); err != nil || !checked {
		t.Fatalf("ReadTypeCheckedFlag() = %t, %v", checked, err)
	}
	if status, err := reader.ReadUint32(); err != nil || status != uint32(StatusNoError) {
		t.Fatalf("status = %d, %v", status, err)
	}
	if seed, err := reader.ReadUint32(); err != nil || seed != 0x12345678 {
		t.Fatalf("ticket seed = 0x%08x, %v", seed, err)
	}
	reader.SetTypeChecked(false)
	ticket, err := reader.ReadRaw(authTicketSize)
	if err != nil {
		t.Fatal(err)
	}
	if reader.RemainingBits() != 5 || body[len(body)-1]&0xf8 != 0 {
		t.Fatalf("unexpected response padding: remaining=%d last=%02x", reader.RemainingBits(), body[len(body)-1])
	}
	plaintext, err := bitdemon.Decrypt3DESCBC(account.PasswordHash[:], bitdemon.DeriveIV(0x12345678), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(plaintext[0:4]) != authTicketSignature || plaintext[4] != authTicketTypeUserToService {
		t.Fatalf("ticket header = %x", plaintext[:5])
	}
	if binary.LittleEndian.Uint32(plaintext[5:9]) != BOZTitleID || binary.LittleEndian.Uint64(plaintext[25:33]) != account.UserID {
		t.Fatal("ticket identity fields do not match")
	}
	if !bytes.Equal(plaintext[33:97], append([]byte(account.Username), make([]byte, accountUsernameSize-len(account.Username))...)) {
		t.Fatal("ticket username does not match")
	}
	if !bytes.Equal(plaintext[97:121], sessionKey[:]) || !allZero(plaintext[121:128]) {
		t.Fatal("ticket session key or trailing bytes do not match")
	}
}
