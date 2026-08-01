package stun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestResponderAnswersObservedZeroChangeRequest(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		SourceAddress:  netip.MustParseAddrPort("192.0.2.10:3478"),
		ChangedAddress: netip.MustParseAddrPort("192.0.2.10:3478"),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := mustDecodeHex(t, "00010008000102030405060708090a0b0c0d0e0f0003000400000000")
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 50117}
	connection := &testPacketConn{}
	if err := responder.HandleUDP(context.Background(), connection, peer, request); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(connection.payload, mustDecodeHex(t,
		"01010024"+
			"000102030405060708090a0b0c0d0e0f"+
			"000100080001c3c5cb007109"+
			"0004000800010d96c000020a"+
			"0005000800010d96c000020a")) {
		t.Fatalf("response = %x", connection.payload)
	}
	if connection.peer.String() != peer.String() {
		t.Fatalf("response peer = %v, want %v", connection.peer, peer)
	}
}

type testPacketConn struct {
	payload []byte
	peer    net.Addr
}

func (connection *testPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (connection *testPacketConn) WriteTo(payload []byte, peer net.Addr) (int, error) {
	connection.payload = append([]byte(nil), payload...)
	connection.peer = peer
	return len(payload), nil
}

func (connection *testPacketConn) Close() error                     { return nil }
func (connection *testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (connection *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (connection *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *testPacketConn) SetWriteDeadline(time.Time) error { return nil }
