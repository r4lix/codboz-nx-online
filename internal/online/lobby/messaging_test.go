package lobby

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestParseMessagingRequestGolden(t *testing.T) {
	payload := []byte{
		0x03, 0x0e,
		0x0a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x13, 0x08, 0x03, 0x00, 0x00, 0x00, 'C', 'O', 'D',
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	request, err := parseMessagingRequest(payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if request.Task != MessagingTaskSendGlobalInstantMessage ||
		request.Recipient != 0x0102030405060708 ||
		!bytes.Equal(request.Message, []byte("COD")) {
		t.Fatalf("request = %#v", request)
	}
	request.Message[0] = 'X'
	if payload[17] != 'C' {
		t.Fatal("parsed message aliases request storage")
	}
}

func TestParseMessagingRequestRejectsMalformedValues(t *testing.T) {
	valid := makeMessagingRequestPayload(t, 7, []byte("COD"))
	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{name: "wrong task type", payload: mutateMessaging(valid, func(value []byte) { value[0] = byte(bitdemon.TypeUint32) }), want: ErrMalformedMessagingRequest},
		{name: "unsupported task", payload: mutateMessaging(valid, func(value []byte) { value[1] = 13 }), want: ErrUnsupportedMessagingTask},
		{name: "wrong recipient type", payload: mutateMessaging(valid, func(value []byte) { value[2] = byte(bitdemon.TypeUint32) }), want: ErrMalformedMessagingRequest},
		{name: "wrong blob type", payload: mutateMessaging(valid, func(value []byte) { value[11] = byte(bitdemon.TypeString) }), want: ErrMalformedMessagingRequest},
		{name: "truncated", payload: valid[:len(valid)-1], want: ErrMalformedMessagingRequest},
		{name: "nonzero padding", payload: mutateMessaging(valid, func(value []byte) { value[len(value)-1] = 1 }), want: ErrMalformedMessagingRequest},
		{name: "excess padding", payload: append(bytes.Clone(valid), make([]byte, bitdemon.TripleDESBlockSize)...), want: ErrMalformedMessagingRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseMessagingRequest(test.payload, 0); !errors.Is(err, test.want) {
				t.Fatalf("parseMessagingRequest() error = %v, want %v", err, test.want)
			}
		})
	}

	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(MessagingTaskSendGlobalInstantMessage)
	writer.WriteUint64(7)
	if err := writer.WriteBlob(bytes.Repeat([]byte{1}, maxMessagingMessageBytes+1)); err != nil {
		t.Fatal(err)
	}
	oversized := padMessagingRequest(writer.Bytes())
	if _, err := parseMessagingRequest(oversized, 0); !errors.Is(err, ErrMalformedMessagingRequest) {
		t.Fatalf("oversized message error = %v", err)
	}
}

func TestMarshalGlobalInstantMessagePushGolden(t *testing.T) {
	var sessionKey [bitdemon.SessionKeySize]byte
	for index := range sessionKey {
		sessionKey[index] = byte(index + 1)
	}
	body, err := marshalGlobalInstantMessagePush(
		sessionKey,
		0x12345678,
		0x0102030405060708,
		"GEN__host",
		[]byte("C10.0.0.2:3074#198.51.100.2:3074?0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("01785634127c571c374ffcf7d29ff1374b53a587728c43115e10a7be4ca968198ab9ce8eb1e7cf8204316242166f47160a885690207bf0692894ddc43289cf525a445c4c415d868934169eca31")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("push body = %x, want %x", body, want)
	}

	if body[0] != 1 || binary.LittleEndian.Uint32(body[1:5]) != 0x12345678 {
		t.Fatalf("encrypted envelope = %x", body[:5])
	}
	plaintext, err := bitdemon.Decrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(0x12345678), body[5:])
	if err != nil {
		t.Fatal(err)
	}
	wantPlaintext := []byte{
		0xef, 0xbe, 0xad, 0xde, 0x02,
		0x08, 0x15, 0x00, 0x00, 0x00,
		0x0a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x10, 'G', 'E', 'N', '_', '_', 'h', 'o', 's', 't', 0x00,
		0x13, 0x08, 0x22, 0x00, 0x00, 0x00,
	}
	wantPlaintext = append(wantPlaintext, []byte("C10.0.0.2:3074#198.51.100.2:3074?0")...)
	wantPlaintext = bitdemon.PadTo3DESBlock(wantPlaintext)
	if !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatalf("push plaintext = %x, want %x", plaintext, wantPlaintext)
	}
}

func TestMarshalGlobalInstantMessagePushRejectsInvalidValues(t *testing.T) {
	var key [bitdemon.SessionKeySize]byte
	tests := []struct {
		name    string
		sender  string
		message []byte
	}{
		{name: "long sender", sender: strings.Repeat("a", maxMessagingSenderNameBytes+1)},
		{name: "embedded nul", sender: "host\x00ignored"},
		{name: "large message", message: bytes.Repeat([]byte{1}, maxMessagingMessageBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := marshalGlobalInstantMessagePush(key, 1, 2, test.sender, test.message); !errors.Is(err, ErrInvalidGlobalInstantMessage) {
				t.Fatalf("marshalGlobalInstantMessagePush() error = %v, want %v", err, ErrInvalidGlobalInstantMessage)
			}
		})
	}
}

func makeMessagingRequestPayload(t *testing.T, recipientID uint64, message []byte) []byte {
	t.Helper()
	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(MessagingTaskSendGlobalInstantMessage)
	writer.WriteUint64(recipientID)
	if err := writer.WriteBlob(message); err != nil {
		t.Fatal(err)
	}
	return padMessagingRequest(writer.Bytes())
}

func padMessagingRequest(payload []byte) []byte {
	return appendClientRequestPadding(payload, 0)
}

func mutateMessaging(value []byte, mutate func([]byte)) []byte {
	result := bytes.Clone(value)
	mutate(result)
	return result
}
