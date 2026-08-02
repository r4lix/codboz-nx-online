package stun

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func TestParseBindingRequestObservedBOZShape(t *testing.T) {
	packet := mustDecodeHex(t, "00010008000102030405060708090a0b0c0d0e0f0003000400000000")

	request, err := ParseBindingRequest(packet)
	if err != nil {
		t.Fatalf("ParseBindingRequest() error = %v", err)
	}

	wantTransaction := TransactionID{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	if request.TransactionID != wantTransaction {
		t.Fatalf("TransactionID = %x, want %x", request.TransactionID, wantTransaction)
	}
	if request.ChangeIP || request.ChangePort {
		t.Fatalf("change flags = (IP %t, port %t), want both false", request.ChangeIP, request.ChangePort)
	}
}

func TestParseBindingRequestDefinedChangeFlags(t *testing.T) {
	tests := []struct {
		name       string
		flags      string
		changeIP   bool
		changePort bool
	}{
		{name: "change port", flags: "00000002", changePort: true},
		{name: "change IP", flags: "00000004", changeIP: true},
		{name: "change IP and port", flags: "00000006", changeIP: true, changePort: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := mustDecodeHex(t, "00010008000102030405060708090a0b0c0d0e0f00030004"+test.flags)
			request, err := ParseBindingRequest(packet)
			if err != nil {
				t.Fatalf("ParseBindingRequest() error = %v", err)
			}
			if request.ChangeIP != test.changeIP || request.ChangePort != test.changePort {
				t.Fatalf("change flags = (IP %t, port %t), want (IP %t, port %t)", request.ChangeIP, request.ChangePort, test.changeIP, test.changePort)
			}
		})
	}
}

func TestParseBindingRequestRejectsInvalidPackets(t *testing.T) {
	valid := mustDecodeHex(t, "00010008000102030405060708090a0b0c0d0e0f0003000400000000")
	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{name: "empty", packet: nil, want: ErrMalformedRequest},
		{name: "truncated header", packet: append([]byte(nil), valid[:19]...), want: ErrMalformedRequest},
		{name: "wrong message type", packet: replaceUint16(valid, 0, 0x0101), want: ErrUnsupportedMessageType},
		{name: "short declared body", packet: replaceUint16(valid, 2, 4), want: ErrMalformedRequest},
		{name: "trailing byte", packet: append(append([]byte(nil), valid...), 0), want: ErrMalformedRequest},
		{name: "unsupported attribute", packet: replaceUint16(valid, HeaderSize, mappedAddressAttribute), want: ErrUnsupportedAttribute},
		{name: "short change attribute", packet: replaceUint16(valid, HeaderSize+2, 3), want: ErrMalformedRequest},
		{name: "reserved change flag", packet: replaceUint32(valid, HeaderSize+4, 1), want: ErrUnsupportedChangeRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseBindingRequest(test.packet)
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseBindingRequest() error = %v, want error matching %v", err, test.want)
			}
		})
	}
}

func TestBuildBindingResponseExactWireLayout(t *testing.T) {
	request := BindingRequest{TransactionID: TransactionID{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}}
	endpoints := BindingResponseEndpoints{
		MappedAddress:  netip.MustParseAddrPort("203.0.113.9:50117"),
		SourceAddress:  netip.MustParseAddrPort("192.0.2.10:3478"),
		ChangedAddress: netip.MustParseAddrPort("198.51.100.20:3479"),
	}

	response, err := BuildBindingResponse(request, endpoints)
	if err != nil {
		t.Fatalf("BuildBindingResponse() error = %v", err)
	}

	want := mustDecodeHex(t,
		"01010024"+
			"000102030405060708090a0b0c0d0e0f"+
			"000100080001c3c5cb007109"+
			"0004000800010d96c000020a"+
			"0005000800010d97c6336414",
	)
	if !bytes.Equal(response, want) {
		t.Fatalf("response = %x\nwant     = %x", response, want)
	}
	if len(response) != BindingResponseSize {
		t.Fatalf("len(response) = %d, want %d", len(response), BindingResponseSize)
	}
}

func TestBuildBindingResponseAllowsLinkLocalMappedAddress(t *testing.T) {
	endpoint := netip.MustParseAddrPort("169.254.20.30:50117")
	_, err := BuildBindingResponse(BindingRequest{}, BindingResponseEndpoints{
		MappedAddress:  endpoint,
		SourceAddress:  netip.MustParseAddrPort("169.254.20.1:3478"),
		ChangedAddress: netip.MustParseAddrPort("169.254.20.2:3479"),
	})
	if err != nil {
		t.Fatalf("BuildBindingResponse() rejected link-local unicast endpoints: %v", err)
	}
}

func TestBuildBindingResponseRejectsInvalidEndpoints(t *testing.T) {
	valid := netip.MustParseAddrPort("192.0.2.10:3478")
	tests := []struct {
		name      string
		endpoints BindingResponseEndpoints
		want      error
	}{
		{
			name: "invalid mapped address",
			endpoints: BindingResponseEndpoints{
				SourceAddress: valid, ChangedAddress: valid,
			},
			want: ErrInvalidEndpoint,
		},
		{
			name: "zero source port",
			endpoints: BindingResponseEndpoints{
				MappedAddress: valid, SourceAddress: netip.MustParseAddrPort("192.0.2.10:0"), ChangedAddress: valid,
			},
			want: ErrInvalidEndpoint,
		},
		{
			name: "unspecified changed address",
			endpoints: BindingResponseEndpoints{
				MappedAddress: valid, SourceAddress: valid, ChangedAddress: netip.MustParseAddrPort("0.0.0.0:3478"),
			},
			want: ErrInvalidEndpoint,
		},
		{
			name: "IPv6 mapped address",
			endpoints: BindingResponseEndpoints{
				MappedAddress: netip.MustParseAddrPort("[2001:db8::1]:3478"), SourceAddress: valid, ChangedAddress: valid,
			},
			want: ErrIPv4Only,
		},
		{
			name: "multicast source address",
			endpoints: BindingResponseEndpoints{
				MappedAddress: valid, SourceAddress: netip.MustParseAddrPort("224.0.0.1:3478"), ChangedAddress: valid,
			},
			want: ErrInvalidEndpoint,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildBindingResponse(BindingRequest{}, test.endpoints)
			if !errors.Is(err, test.want) {
				t.Fatalf("BuildBindingResponse() error = %v, want error matching %v", err, test.want)
			}
		})
	}
}

func FuzzParseBindingRequest(f *testing.F) {
	f.Add(mustDecodeHex(f, "00010008000102030405060708090a0b0c0d0e0f0003000400000000"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = ParseBindingRequest(packet)
	})
}

type testingTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

func mustDecodeHex(tb testingTB, value string) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		tb.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}

func replaceUint16(packet []byte, offset int, value uint16) []byte {
	result := append([]byte(nil), packet...)
	result[offset] = byte(value >> 8)
	result[offset+1] = byte(value)
	return result
}

func replaceUint32(packet []byte, offset int, value uint32) []byte {
	result := append([]byte(nil), packet...)
	result[offset] = byte(value >> 24)
	result[offset+1] = byte(value >> 16)
	result[offset+2] = byte(value >> 8)
	result[offset+3] = byte(value)
	return result
}
