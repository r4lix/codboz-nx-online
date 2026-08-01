package auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestHandlerServesCreateAccountAndIdempotentRetry(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{MaxAccounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{WriteTimeout: time.Second}, store, sessions)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	trackedServerConnection := &readDeadlineTrackingConn{Conn: serverConnection}
	result := make(chan error, 1)
	go func() { result <- handler.HandleTCP(context.Background(), trackedServerConnection) }()
	defer serverConnection.Close()

	if err := bitdemon.WriteFrame(clientConnection, nil); err != nil {
		t.Fatal(err)
	}
	keepalive, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if keepalive.Kind != bitdemon.RecordKindKeepalive {
		t.Fatalf("response kind = %d, want keepalive", keepalive.Kind)
	}

	requestBody := makeCreateAccountBody(t, 0x12345678, "GEN__fixture", bitdemon.Tiger192([]byte("fixture")))
	statuses := []Status{StatusNoError, StatusCreateUsernameExists}
	for _, status := range statuses {
		if err := bitdemon.WriteFrame(clientConnection, requestBody); err != nil {
			t.Fatal(err)
		}
		reply, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Kind != bitdemon.RecordKindFrame {
			t.Fatalf("response kind = %d, want frame", reply.Kind)
		}
		if want := MarshalCreateAccountReplyBody(status); !bytes.Equal(reply.Body, want) {
			t.Fatalf("reply = %x, want %x", reply.Body, want)
		}
	}
	_ = clientConnection.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if trackedServerConnection.readDeadlineCalls != 1 {
		t.Fatalf("read deadline calls = %d, want one absolute handshake deadline", trackedServerConnection.readDeadlineCalls)
	}
}

func TestHandlerRejectsUnsupportedAuthMessage(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{MaxAccounts: 1})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{}, store, sessions)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- handler.HandleTCP(context.Background(), serverConnection) }()
	if err := bitdemon.WriteFrame(clientConnection, []byte{0, 0x07}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrUnsupportedAuthMessage) {
		t.Fatalf("HandleTCP() error = %v, want %v", err, ErrUnsupportedAuthMessage)
	}
	_ = clientConnection.Close()
	_ = serverConnection.Close()
}

type readDeadlineTrackingConn struct {
	net.Conn
	readDeadlineCalls int
}

func (connection *readDeadlineTrackingConn) SetReadDeadline(deadline time.Time) error {
	connection.readDeadlineCalls++
	return connection.Conn.SetReadDeadline(deadline)
}

func TestHandlerIssuesShortTicketAndPendingLobbySession(t *testing.T) {
	accounts, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{MaxAccounts: 1})
	if err != nil {
		t.Fatal(err)
	}
	passwordHash := bitdemon.Tiger192([]byte("fixture password"))
	account, _, err := accounts.Register("GEN__fixture", passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	randomBytes := make([]byte, bitdemon.SessionKeySize+4)
	for index := range randomBytes {
		randomBytes[index] = byte(index + 1)
	}
	now := time.Unix(1_800_000_000, 0)
	handler, err := NewHandler(HandlerConfig{
		WriteTimeout: time.Second,
		Random:       bytes.NewReader(randomBytes),
		Now:          func() time.Time { return now },
	}, accounts, sessions)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	result := make(chan error, 1)
	go func() { result <- handler.HandleTCP(context.Background(), serverConnection) }()
	defer serverConnection.Close()

	writer := bitdemon.NewBitWriter(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(0x01020304)
	writer.WriteUint32(BOZTitleID)
	writer.SetTypeChecked(false)
	var accountHash [8]byte
	binary.LittleEndian.PutUint64(accountHash[:], account.AccountHash)
	writer.WriteRaw(accountHash[:])
	requestBody := append([]byte{0, MessageAccountForMMPRequest}, writer.Bytes()...)
	if err := bitdemon.WriteFrame(clientConnection, requestBody); err != nil {
		t.Fatal(err)
	}
	reply, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Kind != bitdemon.RecordKindFrame || len(reply.Body) != 140 {
		t.Fatalf("AccountForMMP reply = kind %d body length %d", reply.Kind, len(reply.Body))
	}
	reader := bitdemon.NewBitReader(reply.Body[2:])
	if checked, err := reader.ReadTypeCheckedFlag(); err != nil || !checked {
		t.Fatalf("reply type flag = %t, %v", checked, err)
	}
	if status, err := reader.ReadUint32(); err != nil || status != uint32(StatusNoError) {
		t.Fatalf("reply status = %d, %v", status, err)
	}
	ticketSeed, err := reader.ReadUint32()
	if err != nil {
		t.Fatal(err)
	}
	wantSeed := uint32(0x1c1b1a19)
	if ticketSeed != wantSeed {
		t.Fatalf("ticket seed = 0x%08x, want 0x%08x", ticketSeed, wantSeed)
	}
	reader.SetTypeChecked(false)
	ticket, err := reader.ReadRaw(authTicketSize)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := bitdemon.Decrypt3DESCBC(passwordHash[:], bitdemon.DeriveIV(ticketSeed), ticket)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext[97:121], randomBytes[:bitdemon.SessionKeySize]) {
		t.Fatalf("ticket session key = %x", plaintext[97:121])
	}
	pending, _, ok := sessions.Lookup(ticketSeed, serverConnection.RemoteAddr(), now)
	if !ok || pending.UserID != account.UserID || !bytes.Equal(pending.SessionKey[:], randomBytes[:bitdemon.SessionKeySize]) {
		t.Fatalf("pending lobby session = %#v, found=%t", pending, ok)
	}
	_ = clientConnection.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
