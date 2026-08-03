package lobby

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

func TestDecryptRequestBodyAuthenticatesServicePayloadAndPadding(t *testing.T) {
	var sessionKey [bitdemon.SessionKeySize]byte
	payloadWriter := bitdemon.NewByteWriter(true)
	payloadWriter.WriteUint8(EventLogTaskLog)
	if err := payloadWriter.WriteBlob(bytes.Repeat([]byte{0xa5}, 232)); err != nil {
		t.Fatal(err)
	}
	payloadWriter.WriteUint32(2)
	plaintext := append(make([]byte, bitdemon.TruncatedHMACSize), EventLogServiceID)
	plaintext = append(plaintext, appendClientRequestPadding(payloadWriter.Bytes(), 0)...)
	digest := bitdemon.TruncatedHMACSHA1(sessionKey[:], plaintext[5:])
	copy(plaintext[:4], digest[:])
	ciphertext, err := bitdemon.Encrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(0), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{1, 0, 0, 0, 0}, ciphertext...)
	request, err := decryptRequestBody(body, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if request.Seed != 0 || request.Service != EventLogServiceID || !bytes.Equal(request.Payload, plaintext[5:]) {
		t.Fatalf("request = %#v", request)
	}
	body[len(body)-1] ^= 1
	if _, err := decryptRequestBody(body, sessionKey); !errors.Is(err, ErrInvalidRequestHMAC) {
		t.Fatalf("tampered request error = %v, want %v", err, ErrInvalidRequestHMAC)
	}
}

func TestValidClientRequestPadding(t *testing.T) {
	for _, test := range []struct {
		padding []byte
		seed    uint32
	}{
		{padding: []byte{0}, seed: 9},
		{padding: []byte{0, 1, 1, 1, 1, 1, 1, 1}, seed: 1},
		{padding: make([]byte, bitdemon.TripleDESBlockSize), seed: 0},
		{padding: []byte{0, 0xff, 0xff}, seed: 0x1234ff},
	} {
		if !validClientRequestPadding(test.padding, test.seed) {
			t.Fatalf("valid padding %x for seed %08x rejected", test.padding, test.seed)
		}
	}
	for _, padding := range [][]byte{
		nil,
		make([]byte, bitdemon.TripleDESBlockSize+1),
		{1},
		{0, 1, 2},
	} {
		if validClientRequestPadding(padding, 1) {
			t.Fatalf("invalid padding %x accepted", padding)
		}
	}
}

func TestMarshalClearEventLogReplyMatchesObservedFrame(t *testing.T) {
	logical := marshalTaskReply(0, EventLogTaskLog, statusNoError, 0, 0)
	wantLogical := []byte{
		0x01,
		0x0a, 0, 0, 0, 0, 0, 0, 0, 0,
		0x08, 0, 0, 0, 0,
		0x03, 0x02,
		0x08, 0, 0, 0, 0,
	}
	if !bytes.Equal(logical, wantLogical) {
		t.Fatalf("logical reply = %x, want %x", logical, wantLogical)
	}
	body := marshalClearTaskReplyBody(logical)
	frame, err := bitdemon.MarshalFrame(body)
	if err != nil {
		t.Fatal(err)
	}
	wantFrame := append([]byte{0x17, 0, 0, 0, 0}, wantLogical...)
	if !bytes.Equal(frame, wantFrame) {
		t.Fatalf("reply frame = %x, want %x", frame, wantFrame)
	}
}

func TestMarshalClearTaskReplyBodyReservesTwoHundredByteLength(t *testing.T) {
	logical := bytes.Repeat([]byte{0xa5}, reservedClearTaskReplyBodySize-1)
	body := marshalClearTaskReplyBody(logical)
	if len(body) != reservedClearTaskReplyBodySize+1 || body[0] != 0 || body[len(body)-1] != 0 {
		t.Fatalf("reserved body = %x", body)
	}
	if !bytes.Equal(body[1:len(body)-1], logical) {
		t.Fatal("reserved byte changed the logical task reply")
	}
	frame, err := bitdemon.MarshalFrame(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(frame[:4]); got != reservedClearTaskReplyBodySize+1 {
		t.Fatalf("frame body length = %d", got)
	}
}

func appendClientRequestPadding(payload []byte, seed uint32) []byte {
	paddingLength := bitdemon.TripleDESBlockSize -
		(len(payload)+bitdemon.TruncatedHMACSize+1)%bitdemon.TripleDESBlockSize
	result := append(bytes.Clone(payload), make([]byte, paddingLength)...)
	for index := len(payload) + 1; index < len(result); index++ {
		result[index] = byte(seed)
	}
	return result
}
