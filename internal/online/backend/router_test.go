package backend

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestTCPRouterPreservesLeadingRecordsAndRoutesAuth(t *testing.T) {
	authHandler := &recordingHandler{}
	lobbyHandler := &recordingHandler{}
	router, err := NewTCPRouter(authHandler, lobbyHandler)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- router.HandleTCP(context.Background(), serverConnection) }()
	request := []byte{0, 0x00}
	if err := bitdemon.WriteFrame(clientConnection, nil); err != nil {
		t.Fatal(err)
	}
	if err := bitdemon.WriteFrame(clientConnection, request); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if authHandler.body == nil || lobbyHandler.body != nil {
		t.Fatalf("auth body = %x, lobby body = %x", authHandler.body, lobbyHandler.body)
	}
	_ = clientConnection.Close()
	_ = serverConnection.Close()
}

func TestTCPRouterTimesOutIncompleteInitialRecords(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "no input"},
		{name: "partial prefix", payload: []byte{0x74, 0x00}},
		{name: "partial lobby login", payload: []byte{0x8c, 0x00, 0x00, 0x00, 0x00, 0x07}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, err := newTCPRouter(&recordingHandler{}, &recordingHandler{}, 20*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			serverConnection, clientConnection := net.Pipe()
			defer serverConnection.Close()
			defer clientConnection.Close()
			result := make(chan error, 1)
			go func() { result <- router.HandleTCP(context.Background(), serverConnection) }()
			if len(test.payload) != 0 {
				if _, err := clientConnection.Write(test.payload); err != nil {
					t.Fatal(err)
				}
			}
			err = <-result
			var networkError net.Error
			if !errors.As(err, &networkError) || !networkError.Timeout() {
				t.Fatalf("HandleTCP() error = %v, want timeout", err)
			}
		})
	}
}

func TestTCPRouterPreservesBufferMarkerAndRoutesLobby(t *testing.T) {
	authHandler := &recordingHandler{}
	lobbyHandler := &recordingHandler{}
	router, err := NewTCPRouter(authHandler, lobbyHandler)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- router.HandleTCP(context.Background(), serverConnection) }()
	if err := bitdemon.WriteBufferAvailableRecord(clientConnection, 65535); err != nil {
		t.Fatal(err)
	}
	if err := bitdemon.WriteFrame(clientConnection, []byte{0, 0x07}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if lobbyHandler.body == nil || authHandler.body != nil {
		t.Fatalf("auth body = %x, lobby body = %x", authHandler.body, lobbyHandler.body)
	}
	_ = clientConnection.Close()
	_ = serverConnection.Close()
}

type recordingHandler struct {
	body []byte
}

func (handler *recordingHandler) HandleTCP(_ context.Context, connection net.Conn) error {
	for {
		record, err := bitdemon.ReadTransportRecord(connection, bitdemon.DefaultMaxFrameBody)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if record.Kind == bitdemon.RecordKindFrame {
			handler.body = record.Body
			return nil
		}
	}
}
