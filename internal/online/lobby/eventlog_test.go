package lobby

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestParseEventLogRequest(t *testing.T) {
	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(EventLogTaskLog)
	blob := bytes.Repeat([]byte{0x5a}, 232)
	if err := writer.WriteBlob(blob); err != nil {
		t.Fatal(err)
	}
	writer.WriteUint32(2)
	const seed = 6
	payload := appendClientRequestPadding(writer.Bytes(), seed)
	request, err := parseEventLogRequest(payload, seed)
	if err != nil {
		t.Fatal(err)
	}
	if request.Task != EventLogTaskLog || request.Category != 2 || !bytes.Equal(request.Blob, blob) {
		t.Fatalf("request = %#v", request)
	}
	payload[len(payload)-1] = 1
	if _, err := parseEventLogRequest(payload, seed); !errors.Is(err, ErrMalformedEventLogRequest) {
		t.Fatalf("invalid padding error = %v, want %v", err, ErrMalformedEventLogRequest)
	}
}
