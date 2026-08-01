package server

import (
	"context"
	"net"
	"testing"
	"time"
)

type noOpHandler struct{}

func (noOpHandler) HandleTCP(_ context.Context, _ net.Conn) error { return nil }
func (noOpHandler) HandleUDP(_ context.Context, _ net.PacketConn, _ net.Addr, _ []byte) error {
	return nil
}

func TestNewNormalizesDefaults(t *testing.T) {
	service, err := New(Config{}, noOpHandler{})
	if err != nil {
		t.Fatal(err)
	}
	if service.config != DefaultConfig() {
		t.Fatalf("config = %#v, want %#v", service.config, DefaultConfig())
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []Config{
		{MaxTCPConnections: -1},
		{MaxTCPConnections: MaxTCPConnectionsLimit + 1},
		{MaxTCPConnectionsPerSource: -1},
		{MaxTCPConnectionsPerSource: MaxTCPConnectionsPerSourceLimit + 1},
		{MaxTCPConnections: 4, MaxTCPConnectionsPerSource: 5},
		{ShutdownTimeout: time.Millisecond},
		{ShutdownTimeout: time.Minute + time.Second},
	}
	for _, config := range tests {
		if _, err := New(config, noOpHandler{}); err == nil {
			t.Fatalf("New(%#v) succeeded", config)
		}
	}
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("New accepted a nil handler")
	}
}
