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

	"github.com/Producdevity/cod-boz-online/internal/online/stun"
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

func envFrom(values map[string]string) lookupEnv {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestParseOptionsReadsEnvironment(t *testing.T) {
	opts, err := parseOptionsWithEnv(nil, testLogger(), envFrom(map[string]string{
		envTCPListen:                  "127.0.0.1:4074",
		envUDPListen:                  "127.0.0.1:4478",
		envDataDir:                    "/data",
		envSTUNSource:                 "192.0.2.10:4478",
		envMaxTCPConnections:          "128",
		envMaxTCPConnectionsPerSource: "32",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.tcpAddress != "127.0.0.1:4074" || opts.udpAddress != "127.0.0.1:4478" || opts.dataDir != "/data" {
		t.Fatalf("options = %+v", opts)
	}
	if opts.stunSource != netip.MustParseAddrPort("192.0.2.10:4478") {
		t.Fatalf("STUN endpoint = %s", opts.stunSource)
	}
	if opts.maxTCPConnections != 128 || opts.maxTCPConnectionsPerSource != 32 {
		t.Fatalf("limits = %d, %d", opts.maxTCPConnections, opts.maxTCPConnectionsPerSource)
	}
}

func TestParseOptionsFlagsOverrideEnvironment(t *testing.T) {
	opts, err := parseOptionsWithEnv([]string{
		"--data-dir", "flag-data",
		"--stun-source-address", "192.0.2.20:3478",
	}, testLogger(), envFrom(map[string]string{
		envDataDir:    "env-data",
		envSTUNSource: "192.0.2.10:3478",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.dataDir != "flag-data" || opts.stunSource != netip.MustParseAddrPort("192.0.2.20:3478") {
		t.Fatalf("options = %+v", opts)
	}
}

func TestParseOptionsDefaultsLimits(t *testing.T) {
	opts, err := parseOptionsWithEnv([]string{"--stun-source-address", "192.0.2.10:3478"}, testLogger(), envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if opts.maxTCPConnections != 64 || opts.maxTCPConnectionsPerSource != 8 {
		t.Fatalf("limits = %d, %d; want 64, 8", opts.maxTCPConnections, opts.maxTCPConnectionsPerSource)
	}
}

func TestParseOptionsRejectsBadLimits(t *testing.T) {
	cases := []struct {
		args []string
		env  map[string]string
	}{
		{args: []string{"--max-tcp-connections", "0"}},
		{args: []string{"--max-tcp-connections", "2000"}},
		{args: []string{"--max-tcp-connections-per-source", "0"}},
		{args: []string{"--max-tcp-connections", "4", "--max-tcp-connections-per-source", "8"}},
		{env: map[string]string{envMaxTCPConnections: "many"}},
	}
	for _, tc := range cases {
		args := append([]string{"--stun-source-address", "192.0.2.10:3478"}, tc.args...)
		if _, err := parseOptionsWithEnv(args, testLogger(), envFrom(tc.env)); err == nil {
			t.Fatalf("parseOptionsWithEnv(%q, %v) succeeded", tc.args, tc.env)
		}
	}
}

func withDetectedIPv4(t *testing.T, address string, err error) {
	t.Helper()
	previous := detectOutboundIPv4
	detectOutboundIPv4 = func() (netip.Addr, error) {
		if err != nil {
			return netip.Addr{}, err
		}
		return netip.MustParseAddr(address), nil
	}
	t.Cleanup(func() { detectOutboundIPv4 = previous })
}

func TestParseOptionsAutoSTUNSourceUsesOutboundAddressAndUDPPort(t *testing.T) {
	withDetectedIPv4(t, "192.168.1.20", nil)
	opts, err := parseOptionsWithEnv([]string{
		"--udp-listen", ":4478",
		"--stun-source-address", "auto",
	}, testLogger(), envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if opts.stunSource != netip.MustParseAddrPort("192.168.1.20:4478") || !opts.stunSourceDetected {
		t.Fatalf("STUN endpoint = %s, detected = %v", opts.stunSource, opts.stunSourceDetected)
	}
}

func TestParseOptionsAutoSTUNSourceRejectsUnusableAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "0.0.0.0", "2001:db8::1"} {
		withDetectedIPv4(t, address, nil)
		if _, err := parseOptionsWithEnv([]string{"--stun-source-address", "auto"}, testLogger(), envFrom(nil)); err == nil {
			t.Fatalf("auto STUN source accepted %s", address)
		}
	}
	withDetectedIPv4(t, "", errors.New("no route"))
	if _, err := parseOptionsWithEnv([]string{"--stun-source-address", "auto"}, testLogger(), envFrom(nil)); err == nil {
		t.Fatal("auto STUN source succeeded without a route")
	}
	withDetectedIPv4(t, "192.168.1.20", nil)
	if _, err := parseOptionsWithEnv([]string{"--udp-listen", ":0", "--stun-source-address", "auto"}, testLogger(), envFrom(nil)); err == nil {
		t.Fatal("auto STUN source accepted an ephemeral UDP port")
	}
}

func TestParseOptionsHealthcheckNeedsNoSTUNSource(t *testing.T) {
	opts, err := parseOptionsWithEnv([]string{"--healthcheck"}, testLogger(), envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !opts.healthcheck {
		t.Fatal("healthcheck flag not set")
	}
}

func TestCheckHealth(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	address := listener.Addr().String()
	if err := checkHealth(address, time.Second); err != nil {
		t.Fatalf("checkHealth on a live listener: %v", err)
	}
	listener.Close()
	if err := checkHealth(address, time.Second); err == nil {
		t.Fatal("checkHealth succeeded after the listener closed")
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
	if connection.writeCalls != 2 || len(connection.successfulPayload) != stun.BindingResponseSize {
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
