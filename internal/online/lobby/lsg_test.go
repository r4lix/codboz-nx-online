package lobby

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/auth"
	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestParseLSGLoginBody(t *testing.T) {
	var authBlob [lsgAuthBlobSize]byte
	for index := range authBlob {
		authBlob[index] = byte(index)
	}
	body := makeLSGLoginBody(auth.BOZTitleID, 0x12345678, authBlob)
	login, err := ParseLSGLoginBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if login.TitleID != auth.BOZTitleID || login.TicketSeed != 0x12345678 || login.AuthBlob != authBlob {
		t.Fatalf("login = %#v", login)
	}
}

func TestHandlerAuthenticatesLSGAndReturnsClearConnectionID(t *testing.T) {
	store, err := auth.NewMemoryAccountStoreWithConfig(auth.MemoryAccountStoreConfig{MaxAccounts: 1})
	if err != nil {
		t.Fatal(err)
	}
	account, _, err := store.Register("GEN__fixture", [bitdemon.SessionKeySize]byte{9, 8, 7})
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
	sessionKey := [bitdemon.SessionKeySize]byte{1, 2, 3, 4}
	handler, err := NewHandler(HandlerConfig{
		WriteTimeout: time.Second,
		Random:       bytes.NewReader([]byte{0, 0, 0, 0}),
		Now:          func() time.Time { return now },
	}, store, sessions, matches)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	if _, err := sessions.Reserve(auth.LobbySession{
		TicketSeed:  0xaabbccdd,
		ExpiresAt:   now.Add(time.Hour),
		UserID:      account.UserID,
		TitleID:     auth.BOZTitleID,
		AccountHash: account.AccountHash,
		SessionKey:  sessionKey,
	}, serverConnection.RemoteAddr(), now); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- handler.HandleTCP(context.Background(), serverConnection) }()
	defer serverConnection.Close()

	if err := bitdemon.WriteBufferAvailableRecord(clientConnection, 65535); err != nil {
		t.Fatal(err)
	}
	if err := bitdemon.WriteFrame(clientConnection, makeLSGLoginBody(auth.BOZTitleID, 0xaabbccdd, [lsgAuthBlobSize]byte{})); err != nil {
		t.Fatal(err)
	}
	reply, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Kind != bitdemon.RecordKindFrame || len(reply.Body) != 11 || reply.Body[0] != 0 {
		t.Fatalf("reply = kind %d body %x", reply.Kind, reply.Body)
	}
	want := []byte{0, lsgConnectionIDMessage, byte(bitdemon.TypeUint64), 1, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(reply.Body, want) {
		t.Fatalf("reply body = %x, want %x", reply.Body, want)
	}

	eventWriter := bitdemon.NewByteWriter(true)
	eventWriter.WriteUint8(EventLogTaskLog)
	if err := eventWriter.WriteBlob([]byte("sanitized event")); err != nil {
		t.Fatal(err)
	}
	eventWriter.WriteUint32(2)
	requestBody := makeEncryptedTestRequest(t, sessionKey, 0, EventLogServiceID, eventWriter.Bytes())
	if err := bitdemon.WriteFrame(clientConnection, requestBody); err != nil {
		t.Fatal(err)
	}
	eventReply, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if eventReply.Kind != bitdemon.RecordKindFrame || len(eventReply.Body) != 23 || eventReply.Body[0] != 0 {
		t.Fatalf("EventLog reply = kind %d body %x", eventReply.Kind, eventReply.Body)
	}
	wantEventReply := append([]byte{0}, marshalTaskReply(0, EventLogTaskLog, statusNoError, 0, 0)...)
	if !bytes.Equal(eventReply.Body, wantEventReply) {
		t.Fatalf("EventLog reply body = %x, want %x", eventReply.Body, wantEventReply)
	}
	_ = clientConnection.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHandlerRequiresPromptSessionProof(t *testing.T) {
	handler, sessions, account, sessionKey, now := newProvisionalLobbyFixture(t, HandlerConfig{
		WriteTimeout: time.Second,
		ProofTimeout: 20 * time.Millisecond,
	})
	connection, result := openTestLobbyClient(t, handler, sessions, account, 0x01020304, sessionKey, now)
	defer connection.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("HandleTCP() error = %v, want clean proof timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provisional lobby did not close after proof timeout")
	}
}

func TestHandlerBoundsControlRecordsBeforeSessionProof(t *testing.T) {
	handler, sessions, account, sessionKey, now := newProvisionalLobbyFixture(t, HandlerConfig{
		WriteTimeout:                 time.Second,
		ProofTimeout:                 time.Second,
		MaxProvisionalControlRecords: 2,
	})
	connection, result := openTestLobbyClient(t, handler, sessions, account, 0x01020304, sessionKey, now)
	defer connection.Close()
	for index := 0; index < 2; index++ {
		if err := bitdemon.WriteFrame(connection, nil); err != nil {
			t.Fatal(err)
		}
		reply, err := bitdemon.ReadTransportRecord(connection, bitdemon.DefaultMaxFrameBody)
		if err != nil || reply.Kind != bitdemon.RecordKindKeepalive {
			t.Fatalf("keepalive %d reply = kind %d, error %v", index, reply.Kind, err)
		}
	}
	if err := bitdemon.WriteFrame(connection, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrProvisionalControlLimit) {
			t.Fatalf("HandleTCP() error = %v, want %v", err, ErrProvisionalControlLimit)
		}
	case <-time.After(time.Second):
		t.Fatal("provisional lobby accepted excess control records")
	}
}

func TestTwoLobbyClientsCreateAndFindSameSession(t *testing.T) {
	accounts, err := auth.NewMemoryAccountStoreWithConfig(auth.MemoryAccountStoreConfig{MaxAccounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	hostAccount, _, err := accounts.Register("GEN__host", [bitdemon.SessionKeySize]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	finderAccount, _, err := accounts.Register("GEN__finder", [bitdemon.SessionKeySize]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.NewMemoryLobbySessionStoreWithConfig(auth.MemoryLobbySessionStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	handler, err := NewHandler(HandlerConfig{
		WriteTimeout: time.Second,
		Random:       bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		Now:          func() time.Time { return now },
	}, accounts, sessions, matches)
	if err != nil {
		t.Fatal(err)
	}

	hostKey := [bitdemon.SessionKeySize]byte{1, 2, 3}
	hostClient, hostDone := openTestLobbyClient(t, handler, sessions, hostAccount, 0x11111111, hostKey, now)
	sendTestEventLog(t, hostClient, hostKey, 0)

	info := matchmakingFixture()
	info.HostAddress = []byte{0xaa, 0xbb, 0xcc, 0xdd}
	info.Attributes.AppStringAt130 = hostAccount.Username
	createWriter := bitdemon.NewByteWriter(true)
	createWriter.WriteUint8(MatchmakingTaskCreate)
	writeMatchmakingRequestFixture(t, createWriter, info)
	if err := bitdemon.WriteFrame(hostClient, makeEncryptedTestRequest(t, hostKey, 1, MatchmakingServiceID, createWriter.Bytes())); err != nil {
		t.Fatal(err)
	}
	createReply, err := bitdemon.ReadTransportRecord(hostClient, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if createReply.Kind != bitdemon.RecordKindFrame || len(createReply.Body) != 42 {
		t.Fatalf("create reply = kind %d body %x", createReply.Kind, createReply.Body)
	}

	finderKey := [bitdemon.SessionKeySize]byte{4, 5, 6}
	finderClient, finderDone := openTestLobbyClient(t, handler, sessions, finderAccount, 0x22222222, finderKey, now)
	sendTestEventLog(t, finderClient, finderKey, 0)
	findWriter := bitdemon.NewByteWriter(true)
	findWriter.WriteUint8(MatchmakingTaskFind)
	findWriter.WriteUint32(1)
	findWriter.WriteUint32(0)
	findWriter.WriteUint32(50)
	findWriter.WriteUint32(matchmakingFindQueryKey)
	findWriter.WriteInt32(info.Attributes.AppI32At15C)
	if err := bitdemon.WriteFrame(finderClient, makeEncryptedTestRequest(t, finderKey, 1, MatchmakingServiceID, findWriter.Bytes())); err != nil {
		t.Fatal(err)
	}
	findReply, err := bitdemon.ReadTransportRecord(finderClient, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	reader := bitdemon.NewByteReader(findReply.Body[1:], true)
	if message, err := reader.ReadRaw(1); err != nil || !bytes.Equal(message, []byte{taskReplyMessage}) {
		t.Fatalf("find message = %x, %v", message, err)
	}
	if transaction, err := reader.ReadUint64(); err != nil || transaction != 1 {
		t.Fatalf("find transaction = %d, %v", transaction, err)
	}
	if status, err := reader.ReadUint32(); err != nil || status != 0 {
		t.Fatalf("find status = %d, %v", status, err)
	}
	if operation, err := reader.ReadUint8(); err != nil || operation != MatchmakingTaskFind {
		t.Fatalf("find operation = %d, %v", operation, err)
	}
	if count, err := reader.ReadUint32(); err != nil || count != 1 {
		t.Fatalf("find count = %d, %v", count, err)
	}
	if total, err := reader.ReadUint32(); err != nil || total != 1 {
		t.Fatalf("find total = %d, %v", total, err)
	}
	foundHostAddress, err := reader.ReadBlob(maxHostAddressSize)
	if err != nil || !bytes.Equal(foundHostAddress, info.HostAddress) {
		t.Fatalf("found host address = %x, %v", foundHostAddress, err)
	}
	if _, err := readMatchmakingSessionID(reader); err != nil {
		t.Fatal(err)
	}
	if gameType, err := reader.ReadUint32(); err != nil || gameType != info.GameType {
		t.Fatalf("found game type = %d, %v", gameType, err)
	}

	joinMessage := []byte("C203.0.113.20:50120#192.168.1.20:50120?0")
	messagingWriter := bitdemon.NewByteWriter(true)
	messagingWriter.WriteUint8(MessagingTaskSendGlobalInstantMessage)
	messagingWriter.WriteUint64(hostAccount.AccountHash)
	if err := messagingWriter.WriteBlob(joinMessage); err != nil {
		t.Fatal(err)
	}
	if err := bitdemon.WriteFrame(finderClient, makeEncryptedTestRequest(t, finderKey, 2, MessagingServiceID, messagingWriter.Bytes())); err != nil {
		t.Fatal(err)
	}
	hostPush, err := bitdemon.ReadTransportRecord(hostClient, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	assertGlobalInstantMessagePush(t, hostPush, hostKey, finderAccount, joinMessage)
	messagingReply, err := bitdemon.ReadTransportRecord(finderClient, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	wantMessagingReply := append([]byte{0}, marshalTaskReply(2, MessagingTaskSendGlobalInstantMessage, statusNoError, 0, 0)...)
	if messagingReply.Kind != bitdemon.RecordKindFrame || !bytes.Equal(messagingReply.Body, wantMessagingReply) {
		t.Fatalf("messaging reply = kind %d body %x, want %x", messagingReply.Kind, messagingReply.Body, wantMessagingReply)
	}

	_ = finderClient.Close()
	if err := <-finderDone; err != nil {
		t.Fatal(err)
	}
	_ = hostClient.Close()
	if err := <-hostDone; err != nil {
		t.Fatal(err)
	}
}

func assertGlobalInstantMessagePush(t *testing.T, record bitdemon.TransportRecord, sessionKey [bitdemon.SessionKeySize]byte, sender auth.Account, message []byte) {
	t.Helper()
	if record.Kind != bitdemon.RecordKindFrame || len(record.Body) < 5+bitdemon.TripleDESBlockSize || record.Body[0] != 1 {
		t.Fatalf("push record = kind %d body %x", record.Kind, record.Body)
	}
	seed := binary.LittleEndian.Uint32(record.Body[1:5])
	plaintext, err := bitdemon.Decrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(seed), record.Body[5:])
	if err != nil {
		t.Fatal(err)
	}
	if len(plaintext) < 5 || binary.LittleEndian.Uint32(plaintext[:4]) != serverReplySignature || plaintext[4] != pushMessageType {
		t.Fatalf("push header = %x", plaintext)
	}
	reader := bitdemon.NewByteReader(plaintext[5:], true)
	event, err := reader.ReadUint32()
	if err != nil || event != globalInstantMessageEvent {
		t.Fatalf("push event = %d, %v", event, err)
	}
	senderID, err := reader.ReadUint64()
	if err != nil || senderID != sender.AccountHash {
		t.Fatalf("push sender = %016x, %v", senderID, err)
	}
	senderName, err := reader.ReadString(maxMessagingSenderNameBytes)
	if err != nil || senderName != sender.Username {
		t.Fatalf("push sender name = %q, %v", senderName, err)
	}
	pushedMessage, err := reader.ReadBlob(maxMessagingMessageBytes)
	if err != nil || !bytes.Equal(pushedMessage, message) {
		t.Fatalf("push message = %q, %v", pushedMessage, err)
	}
	padding, err := reader.ReadRaw(uint32(reader.Remaining()))
	if err != nil || !allZero(padding) {
		t.Fatalf("push padding = %x, %v", padding, err)
	}
}

func openTestLobbyClient(t *testing.T, handler *Handler, sessions *auth.MemoryLobbySessionStore, account auth.Account, ticketSeed uint32, sessionKey [bitdemon.SessionKeySize]byte, now time.Time) (net.Conn, <-chan error) {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	if _, err := sessions.Reserve(auth.LobbySession{
		TicketSeed:  ticketSeed,
		ExpiresAt:   now.Add(time.Hour),
		UserID:      account.UserID,
		TitleID:     auth.BOZTitleID,
		AccountHash: account.AccountHash,
		SessionKey:  sessionKey,
	}, serverConnection.RemoteAddr(), now); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- handler.HandleTCP(context.Background(), serverConnection) }()
	if err := bitdemon.WriteFrame(clientConnection, makeLSGLoginBody(auth.BOZTitleID, ticketSeed, [lsgAuthBlobSize]byte{})); err != nil {
		t.Fatal(err)
	}
	reply, err := bitdemon.ReadTransportRecord(clientConnection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Kind != bitdemon.RecordKindFrame || len(reply.Body) != 11 || reply.Body[0] != 0 {
		t.Fatalf("connection ID reply = kind %d body %x", reply.Kind, reply.Body)
	}
	return clientConnection, result
}

func newProvisionalLobbyFixture(t *testing.T, config HandlerConfig) (*Handler, *auth.MemoryLobbySessionStore, auth.Account, [bitdemon.SessionKeySize]byte, time.Time) {
	t.Helper()
	accounts, err := auth.NewMemoryAccountStoreWithConfig(auth.MemoryAccountStoreConfig{MaxAccounts: 1})
	if err != nil {
		t.Fatal(err)
	}
	account, _, err := accounts.Register("GEN__fixture", [bitdemon.SessionKeySize]byte{9, 8, 7})
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
	if config.Now == nil {
		config.Now = func() time.Time { return now }
	}
	handler, err := NewHandler(config, accounts, sessions, matches)
	if err != nil {
		t.Fatal(err)
	}
	return handler, sessions, account, [bitdemon.SessionKeySize]byte{1, 2, 3, 4}, now
}

func sendTestEventLog(t *testing.T, connection net.Conn, sessionKey [bitdemon.SessionKeySize]byte, seed uint32) {
	t.Helper()
	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(EventLogTaskLog)
	if err := writer.WriteBlob([]byte("sanitized event")); err != nil {
		t.Fatal(err)
	}
	writer.WriteUint32(2)
	if err := bitdemon.WriteFrame(connection, makeEncryptedTestRequest(t, sessionKey, seed, EventLogServiceID, writer.Bytes())); err != nil {
		t.Fatal(err)
	}
	reply, err := bitdemon.ReadTransportRecord(connection, bitdemon.DefaultMaxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Kind != bitdemon.RecordKindFrame || len(reply.Body) != 23 {
		t.Fatalf("EventLog reply = kind %d body %x", reply.Kind, reply.Body)
	}
}

func makeEncryptedTestRequest(t *testing.T, sessionKey [bitdemon.SessionKeySize]byte, seed uint32, service byte, payload []byte) []byte {
	t.Helper()
	plaintext := append(make([]byte, bitdemon.TruncatedHMACSize), service)
	plaintext = append(plaintext, appendClientRequestPadding(payload, seed)...)
	digest := bitdemon.TruncatedHMACSHA1(sessionKey[:], plaintext[5:])
	copy(plaintext[:4], digest[:])
	ciphertext, err := bitdemon.Encrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(seed), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 5+len(ciphertext))
	body[0] = 1
	binary.LittleEndian.PutUint32(body[1:5], seed)
	copy(body[5:], ciphertext)
	return body
}

func makeLSGLoginBody(titleID, ticketSeed uint32, authBlob [lsgAuthBlobSize]byte) []byte {
	writer := bitdemon.NewBitWriter(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(titleID)
	writer.WriteUint32(ticketSeed)
	writer.SetTypeChecked(false)
	writer.WriteRaw(authBlob[:])
	return append([]byte{0, LSGServiceID}, writer.Bytes()...)
}
