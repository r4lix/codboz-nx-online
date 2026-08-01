package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/stun"
)

func testLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func TestParseOptionsRequiresSTUNSource(t *testing.T) {
	if _, err := parseOptions(nil, testLogger()); err == nil {
		t.Fatal("parseOptions accepted an empty STUN source")
	}
}

func TestParseOptionsUsesNativeDefaults(t *testing.T) {
	opts, err := parseOptions([]string{
		"--stun-source-address", "192.0.2.10:3478",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if opts.tcpAddress != ":3074" || opts.udpAddress != ":3478" {
		t.Fatalf("listen addresses = %q, %q", opts.tcpAddress, opts.udpAddress)
	}
	if opts.dataDir != "data" {
		t.Fatalf("data directory = %q, want data", opts.dataDir)
	}
	want := netip.MustParseAddrPort("192.0.2.10:3478")
	if opts.stunSource != want {
		t.Fatalf("STUN endpoint = %s; want %s", opts.stunSource, want)
	}
}

func TestParseOptionsAcceptsExplicitEndpoints(t *testing.T) {
	opts, err := parseOptions([]string{
		"--tcp-listen", "127.0.0.1:3074",
		"--udp-listen", "127.0.0.1:3478",
		"--stun-source-address", "192.0.2.10:3478",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if opts.tcpAddress != "127.0.0.1:3074" || opts.udpAddress != "127.0.0.1:3478" {
		t.Fatalf("listen addresses = %q, %q", opts.tcpAddress, opts.udpAddress)
	}
	if opts.stunSource != netip.MustParseAddrPort("192.0.2.10:3478") {
		t.Fatalf("STUN endpoint = %s", opts.stunSource)
	}
}

func TestParseOptionsRejectsMalformedInput(t *testing.T) {
	tests := [][]string{
		{"--stun-source-address", "not-an-address"},
		{"--stun-source-address", "[2001:db8::1]:3478"},
		{"--stun-source-address", "192.0.2.10:3478", "unexpected"},
		{"--stun-source-address", "192.0.2.10:3478", "--tcp-listen", ""},
		{"--stun-source-address", "192.0.2.10:3478", "--data-dir", ""},
	}
	for _, args := range tests {
		if _, err := parseOptions(args, testLogger()); err == nil {
			t.Fatalf("parseOptions(%q) succeeded", args)
		}
	}
}

func TestRuntimeHandlerDropsSTUNWriteErrorAndContinues(t *testing.T) {
	responder, err := stun.NewResponder(stun.ResponderConfig{
		SourceAddress:  netip.MustParseAddrPort("192.0.2.10:3478"),
		ChangedAddress: netip.MustParseAddrPort("192.0.2.10:3478"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := &runtimeHandler{stun: responder, logger: log.New(&logs, "", 0)}
	connection := &failOncePacketConn{}
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 50117}
	request := []byte{
		0x00, 0x01, 0x00, 0x08,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	}

	if err := handler.HandleUDP(context.Background(), connection, peer, request); err != nil {
		t.Fatalf("first HandleUDP() error = %v", err)
	}
	if !strings.Contains(logs.String(), "temporary UDP write failure") {
		t.Fatalf("log output = %q", logs.String())
	}
	if err := handler.HandleUDP(context.Background(), connection, peer, request); err != nil {
		t.Fatalf("second HandleUDP() error = %v", err)
	}
	if connection.writeCalls != 2 || len(connection.successfulPayload) != stun.BindingResponseSize+8 {
		t.Fatalf("writes = %d, successful payload bytes = %d", connection.writeCalls, len(connection.successfulPayload))
	}
}

type failOncePacketConn struct {
	writeCalls        int
	successfulPayload []byte
}

func (connection *failOncePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (connection *failOncePacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	connection.writeCalls++
	if connection.writeCalls == 1 {
		return 0, errors.New("temporary UDP write failure")
	}
	connection.successfulPayload = append([]byte(nil), payload...)
	return len(payload), nil
}

func (connection *failOncePacketConn) Close() error                     { return nil }
func (connection *failOncePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (connection *failOncePacketConn) SetDeadline(time.Time) error      { return nil }
func (connection *failOncePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *failOncePacketConn) SetWriteDeadline(time.Time) error { return nil }
