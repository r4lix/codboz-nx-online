package lobby

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/auth"
	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestActiveLobbyClientsStaleDeactivationPreservesReplacement(t *testing.T) {
	clients := newActiveLobbyClients()
	account := auth.Account{AccountHash: 0x0102030405060708}
	oldConnection := &lobbyTestConn{}
	oldClient := &lobbyClient{connection: oldConnection, account: account}
	replacement := &lobbyClient{connection: &lobbyTestConn{}, account: account}

	clients.activate(oldClient)
	clients.activate(replacement)
	if !oldConnection.isClosed() {
		t.Fatal("activating a replacement did not close the previous connection")
	}

	clients.deactivate(oldClient)
	if got := clients.lookup(account.AccountHash); got != replacement {
		t.Fatalf("stale deactivation replaced active client with %p, want %p", got, replacement)
	}

	clients.deactivate(replacement)
	if got := clients.lookup(account.AccountHash); got != nil {
		t.Fatalf("replacement remains registered after its own deactivation: %p", got)
	}
}

func TestMessagingDeliveryFailureStillAcknowledgesSender(t *testing.T) {
	tests := []struct {
		name              string
		installRecipient  bool
		wantRecipientDrop bool
	}{
		{name: "recipient offline"},
		{name: "recipient write fails", installRecipient: true, wantRecipientDrop: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accounts, err := auth.NewMemoryAccountStoreWithConfig(auth.MemoryAccountStoreConfig{MaxAccounts: 1})
			if err != nil {
				t.Fatal(err)
			}
			senderAccount, _, err := accounts.Register("GEN__sender", [bitdemon.SessionKeySize]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := auth.NewMemoryLobbySessionStoreWithConfig(auth.MemoryLobbySessionStoreConfig{MaxSessions: 1})
			if err != nil {
				t.Fatal(err)
			}
			matches, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 1})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_800_000_000, 0)
			handler, err := NewHandler(HandlerConfig{
				WriteTimeout: time.Second,
				Random:       bytes.NewReader([]byte{1, 2, 3, 4}),
				Now:          func() time.Time { return now },
			}, accounts, sessions, matches)
			if err != nil {
				t.Fatal(err)
			}

			senderKey := [bitdemon.SessionKeySize]byte{1, 2, 3}
			senderConnection, senderDone := openTestLobbyClient(t, handler, sessions, senderAccount, 0x11111111, senderKey, now)
			sendTestEventLog(t, senderConnection, senderKey, 0)

			const recipientHash = uint64(0x8877665544332211)
			var recipientConnection *lobbyTestConn
			if test.installRecipient {
				recipientConnection = &lobbyTestConn{writeErr: errTestRecipientWrite}
				handler.clients.activate(&lobbyClient{
					connection:   recipientConnection,
					writeTimeout: time.Second,
					account:      auth.Account{AccountHash: recipientHash, Username: "GEN__recipient"},
					sessionKey:   [bitdemon.SessionKeySize]byte{4, 5, 6},
				})
			}

			writer := bitdemon.NewByteWriter(true)
			writer.WriteUint8(MessagingTaskSendGlobalInstantMessage)
			writer.WriteUint64(recipientHash)
			if err := writer.WriteBlob([]byte("join request")); err != nil {
				t.Fatal(err)
			}
			if err := bitdemon.WriteFrame(senderConnection, makeEncryptedTestRequest(t, senderKey, 1, MessagingServiceID, writer.Bytes())); err != nil {
				t.Fatal(err)
			}

			reply, err := bitdemon.ReadTransportRecord(senderConnection, bitdemon.DefaultMaxFrameBody)
			if err != nil {
				t.Fatal(err)
			}
			wantReply := append([]byte{0}, marshalTaskReply(1, MessagingTaskSendGlobalInstantMessage, statusNoError, 0, 0)...)
			if reply.Kind != bitdemon.RecordKindFrame || !bytes.Equal(reply.Body, wantReply) {
				t.Fatalf("sender reply = kind %d body %x, want %x", reply.Kind, reply.Body, wantReply)
			}

			if test.wantRecipientDrop {
				if !recipientConnection.isClosed() {
					t.Fatal("failed recipient connection was not closed")
				}
				if got := handler.clients.lookup(recipientHash); got != nil {
					t.Fatalf("failed recipient remains active: %p", got)
				}
			}

			_ = senderConnection.Close()
			if err := <-senderDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLobbyClientWriteFrameSerializesConcurrentPushesAndReplies(t *testing.T) {
	connection := &lobbyTestConn{fragmentWrites: true}
	client := &lobbyClient{connection: connection, writeTimeout: time.Second}
	var sessionKey [bitdemon.SessionKeySize]byte
	for index := range sessionKey {
		sessionKey[index] = byte(index + 1)
	}

	const frameCount = 64
	bodies := make([][]byte, frameCount)
	wantBodies := make(map[string]int, frameCount)
	for index := range bodies {
		var body []byte
		if index%2 == 0 {
			var err error
			body, err = marshalGlobalInstantMessagePush(
				sessionKey,
				uint32(index),
				uint64(index+1),
				"GEN__sender",
				[]byte{byte(index), 0xaa, 0x55},
			)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			body = append([]byte{0}, marshalTaskReply(uint64(index), MessagingTaskSendGlobalInstantMessage, statusNoError, 0, 0)...)
		}
		bodies[index] = body
		wantBodies[string(body)]++
	}

	start := make(chan struct{})
	errorsByWrite := make(chan error, frameCount)
	var writes sync.WaitGroup
	for _, body := range bodies {
		body := body
		writes.Add(1)
		go func() {
			defer writes.Done()
			<-start
			errorsByWrite <- client.writeFrame(body)
		}()
	}
	close(start)
	writes.Wait()
	close(errorsByWrite)
	for err := range errorsByWrite {
		if err != nil {
			t.Fatal(err)
		}
	}

	reader := bytes.NewReader(connection.bytes())
	for index := 0; index < frameCount; index++ {
		record, err := bitdemon.ReadTransportRecord(reader, bitdemon.DefaultMaxFrameBody)
		if err != nil {
			t.Fatalf("read frame %d: %v", index, err)
		}
		if record.Kind != bitdemon.RecordKindFrame {
			t.Fatalf("record %d kind = %d, want frame", index, record.Kind)
		}
		key := string(record.Body)
		if wantBodies[key] == 0 {
			t.Fatalf("record %d is interleaved or unexpected: %x", index, record.Body)
		}
		wantBodies[key]--
	}
	if reader.Len() != 0 {
		t.Fatalf("%d trailing bytes after %d frames", reader.Len(), frameCount)
	}
	for body, remaining := range wantBodies {
		if remaining != 0 {
			t.Fatalf("frame %x remaining count = %d", []byte(body), remaining)
		}
	}
}

var errTestRecipientWrite = errors.New("test recipient write failure")

type lobbyTestConn struct {
	mu             sync.Mutex
	written        []byte
	closed         bool
	writeErr       error
	fragmentWrites bool
}

func (connection *lobbyTestConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (connection *lobbyTestConn) Write(value []byte) (int, error) {
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return 0, net.ErrClosed
	}
	if connection.writeErr != nil {
		err := connection.writeErr
		connection.mu.Unlock()
		return 0, err
	}
	written := len(value)
	if connection.fragmentWrites && written > 1 {
		written = 1
	}
	connection.written = append(connection.written, value[:written]...)
	connection.mu.Unlock()
	if connection.fragmentWrites {
		runtime.Gosched()
	}
	return written, nil
}

func (connection *lobbyTestConn) Close() error {
	connection.mu.Lock()
	connection.closed = true
	connection.mu.Unlock()
	return nil
}

func (connection *lobbyTestConn) LocalAddr() net.Addr {
	return lobbyTestAddr("local")
}

func (connection *lobbyTestConn) RemoteAddr() net.Addr {
	return lobbyTestAddr("remote")
}

func (connection *lobbyTestConn) SetDeadline(time.Time) error {
	return nil
}

func (connection *lobbyTestConn) SetReadDeadline(time.Time) error {
	return nil
}

func (connection *lobbyTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (connection *lobbyTestConn) bytes() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return bytes.Clone(connection.written)
}

func (connection *lobbyTestConn) isClosed() bool {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.closed
}

type lobbyTestAddr string

func (address lobbyTestAddr) Network() string { return "test" }

func (address lobbyTestAddr) String() string { return string(address) }
