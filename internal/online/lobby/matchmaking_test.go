package lobby

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

func TestParseMatchmakingCreateRequestAndWriteResponseInfo(t *testing.T) {
	want := matchmakingFixture()
	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(MatchmakingTaskCreate)
	writeMatchmakingRequestFixture(t, writer, want)
	const seed = 7
	payload := appendClientRequestPadding(writer.Bytes(), seed)
	request, err := parseMatchmakingRequest(payload, seed)
	if err != nil {
		t.Fatal(err)
	}
	want.SessionID = MatchmakingSessionID{}
	want.NumPlayers = 0
	if request.Task != MatchmakingTaskCreate || !reflect.DeepEqual(request.Info, want) {
		t.Fatalf("request = %#v, want info %#v", request, want)
	}

	responseInfo := matchmakingFixture()
	responseWriter := bitdemon.NewByteWriter(true)
	if err := writeMatchmakingResult(responseWriter, responseInfo); err != nil {
		t.Fatal(err)
	}
	reader := bitdemon.NewByteReader(responseWriter.Bytes(), true)
	host, err := reader.ReadBlob(maxHostAddressSize)
	if err != nil || !bytes.Equal(host, responseInfo.HostAddress) {
		t.Fatalf("host address = %x, %v", host, err)
	}
	sessionID, err := readMatchmakingSessionID(reader)
	if err != nil || sessionID != responseInfo.SessionID {
		t.Fatalf("session ID = %x, %v", sessionID, err)
	}
	if gameType, err := reader.ReadUint32(); err != nil || gameType != responseInfo.GameType {
		t.Fatalf("game type = %d, %v", gameType, err)
	}
	if maxPlayers, err := reader.ReadUint32(); err != nil || maxPlayers != responseInfo.MaxPlayers {
		t.Fatalf("max players = %d, %v", maxPlayers, err)
	}
	if numPlayers, err := reader.ReadUint32(); err != nil || numPlayers != responseInfo.NumPlayers {
		t.Fatalf("num players = %d, %v", numPlayers, err)
	}
	attributes, err := readMatchmakingAttributes(reader)
	if err != nil || attributes != responseInfo.Attributes || reader.Remaining() != 0 {
		t.Fatalf("attributes = %#v, remaining=%d, error=%v", attributes, reader.Remaining(), err)
	}
}

func TestMatchmakingStringUsesThirtyTwoByteDestinationCapacity(t *testing.T) {
	info := matchmakingFixture()
	info.Attributes.AppStringAt130 = strings.Repeat("a", 31)
	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint8(MatchmakingTaskCreate)
	writeMatchmakingRequestFixture(t, writer, info)
	if _, err := parseMatchmakingRequest(appendClientRequestPadding(writer.Bytes(), 1), 1); err != nil {
		t.Fatalf("31-byte string rejected: %v", err)
	}

	info.Attributes.AppStringAt130 = strings.Repeat("b", 32)
	writer = bitdemon.NewByteWriter(true)
	writer.WriteUint8(MatchmakingTaskCreate)
	writeMatchmakingRequestFixture(t, writer, info)
	if _, err := parseMatchmakingRequest(writer.Bytes(), 1); !errors.Is(err, ErrMalformedMatchmakingRequest) {
		t.Fatalf("32-byte string error = %v, want %v", err, ErrMalformedMatchmakingRequest)
	}
}

func TestBindMatchmakingIdentityUsesAuthenticatedUsernameForHosting(t *testing.T) {
	for _, task := range []byte{MatchmakingTaskCreate, MatchmakingTaskUpdate} {
		request := MatchmakingRequest{Task: task, Info: matchmakingFixture()}
		originalU64 := request.Info.Attributes.AppU64At128
		bound, err := bindMatchmakingIdentity(request, "GEN__authenticated")
		if err != nil {
			t.Fatal(err)
		}
		if got := bound.Info.Attributes.AppStringAt130; got != "GEN__authenticated" {
			t.Fatalf("task %d identity = %q", task, got)
		}
		if got := bound.Info.Attributes.AppU64At128; got != originalU64 {
			t.Fatalf("task %d app u64 = %d, want %d", task, got, originalU64)
		}
	}

	find := MatchmakingRequest{Task: MatchmakingTaskFind, Info: matchmakingFixture()}
	unchanged, err := bindMatchmakingIdentity(find, "GEN__authenticated")
	if err != nil || !reflect.DeepEqual(unchanged, find) {
		t.Fatalf("find request = %#v, %v", unchanged, err)
	}

	request := MatchmakingRequest{Task: MatchmakingTaskCreate, Info: matchmakingFixture()}
	if _, err := bindMatchmakingIdentity(request, strings.Repeat("x", maxMatchmakingTextBytes+1)); !errors.Is(err, ErrMatchmakingIdentity) {
		t.Fatalf("long identity error = %v, want %v", err, ErrMatchmakingIdentity)
	}
}

func TestHandlerMatchmakingReplyShapes(t *testing.T) {
	store, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		config:  HandlerConfig{Random: bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
		matches: store,
	}
	createBody, err := handler.handleMatchmaking(1, 0, MatchmakingRequest{
		Task: MatchmakingTaskCreate,
		Info: matchmakingFixture(),
	})
	if err != nil {
		t.Fatal(err)
	}
	createFrame, err := bitdemon.MarshalFrame(createBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(createBody) != 42 || len(createFrame) != 46 || !bytes.Equal(createFrame[:5], []byte{0x2a, 0, 0, 0, 0}) {
		t.Fatalf("create frame = %x", createFrame)
	}
	wantCreateTail := []byte{0x13, 0x08, 0x08, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(createBody[len(createBody)-len(wantCreateTail):], wantCreateTail) {
		t.Fatalf("create result = %x, want %x", createBody[len(createBody)-len(wantCreateTail):], wantCreateTail)
	}

	findBody, err := handler.handleMatchmaking(2, 1, MatchmakingRequest{
		Task:       MatchmakingTaskFind,
		NumParams:  1,
		MaxResults: 50,
		Query:      MatchmakingQuery{AttributeHash: 21, AttributeValue: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if findBody[0] != 0 || len(findBody) <= 28 {
		t.Fatalf("find body = %x", findBody)
	}
	header := bitdemon.NewByteReader(findBody[1:], true)
	message, err := header.ReadRaw(1)
	if err != nil || !bytes.Equal(message, []byte{taskReplyMessage}) {
		t.Fatalf("find message = %x, %v", message, err)
	}
	if tx, err := header.ReadUint64(); err != nil || tx != 1 {
		t.Fatalf("find transaction = %d, %v", tx, err)
	}
	if status, err := header.ReadUint32(); err != nil || status != 0 {
		t.Fatalf("find status = %d, %v", status, err)
	}
	if operation, err := header.ReadUint8(); err != nil || operation != MatchmakingTaskFind {
		t.Fatalf("find operation = %d, %v", operation, err)
	}
	if count, err := header.ReadUint32(); err != nil || count != 1 {
		t.Fatalf("find count = %d, %v", count, err)
	}
	if total, err := header.ReadUint32(); err != nil || total != 1 {
		t.Fatalf("find total = %d, %v", total, err)
	}
}

func TestHandlerFindReplyAvoidsReservedTransportLength(t *testing.T) {
	store, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewReader([]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
	})
	for owner := uint64(1); owner <= 2; owner++ {
		if _, err := store.Create(owner, matchmakingFixture(), random); err != nil {
			t.Fatal(err)
		}
	}
	handler := &Handler{matches: store}
	body, err := handler.handleMatchmaking(3, 0, MatchmakingRequest{
		Task:       MatchmakingTaskFind,
		NumParams:  1,
		MaxResults: 2,
		Query:      MatchmakingQuery{AttributeHash: 21, AttributeValue: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == bitdemon.BufferAvailableRecordMarker {
		t.Fatalf("find reply body uses reserved transport length %d", len(body))
	}
	if _, err := bitdemon.MarshalFrame(body); err != nil {
		t.Fatalf("find reply is not frameable: %v", err)
	}
}

func TestHandlerAcknowledgesStaleMatchLifecycleOperations(t *testing.T) {
	store, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		config:  HandlerConfig{Random: bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
		matches: store,
	}
	if _, err := handler.handleMatchmaking(1, 0, MatchmakingRequest{
		Task: MatchmakingTaskCreate,
		Info: matchmakingFixture(),
	}); err != nil {
		t.Fatal(err)
	}
	sessionID := MatchmakingSessionID{1, 2, 3, 4, 5, 6, 7, 8}
	if _, err := handler.handleMatchmaking(1, 1, MatchmakingRequest{
		Task:      MatchmakingTaskDelete,
		SessionID: sessionID,
	}); err != nil {
		t.Fatal(err)
	}

	for transactionID, request := range []MatchmakingRequest{
		{Task: MatchmakingTaskDelete, SessionID: sessionID},
		{Task: MatchmakingTaskUpdate, SessionID: sessionID, Info: matchmakingFixture()},
	} {
		body, err := handler.handleMatchmaking(1, uint64(transactionID+2), request)
		if err != nil {
			t.Fatalf("stale task %d error = %v", request.Task, err)
		}
		reader := bitdemon.NewByteReader(body[1:], true)
		if _, err := reader.ReadRaw(1); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadUint64(); err != nil {
			t.Fatal(err)
		}
		if status, err := reader.ReadUint32(); err != nil || status != statusNoError {
			t.Fatalf("stale task %d status = %d, %v", request.Task, status, err)
		}
		if task, err := reader.ReadUint8(); err != nil || task != request.Task {
			t.Fatalf("stale task operation = %d, %v, want %d", task, err, request.Task)
		}
	}
}

func TestParseMatchmakingUpdateDeleteAndFindRequests(t *testing.T) {
	info := matchmakingFixture()

	updateWriter := bitdemon.NewByteWriter(true)
	updateWriter.WriteUint8(MatchmakingTaskUpdate)
	if err := writeMatchmakingSessionID(updateWriter, info.SessionID); err != nil {
		t.Fatal(err)
	}
	writeMatchmakingRequestFixture(t, updateWriter, info)
	update, err := parseMatchmakingRequest(appendClientRequestPadding(updateWriter.Bytes(), 2), 2)
	if err != nil || update.Task != MatchmakingTaskUpdate || update.SessionID != info.SessionID {
		t.Fatalf("update = %#v, %v", update, err)
	}

	deleteWriter := bitdemon.NewByteWriter(true)
	deleteWriter.WriteUint8(MatchmakingTaskDelete)
	if err := writeMatchmakingSessionID(deleteWriter, info.SessionID); err != nil {
		t.Fatal(err)
	}
	deletion, err := parseMatchmakingRequest(appendClientRequestPadding(deleteWriter.Bytes(), 3), 3)
	if err != nil || deletion.Task != MatchmakingTaskDelete || deletion.SessionID != info.SessionID {
		t.Fatalf("delete = %#v, %v", deletion, err)
	}

	findWriter := bitdemon.NewByteWriter(true)
	findWriter.WriteUint8(MatchmakingTaskFind)
	findWriter.WriteUint32(1)
	findWriter.WriteUint32(0)
	findWriter.WriteUint32(50)
	findWriter.WriteUint32(0x11223344)
	findWriter.WriteInt32(1)
	find, err := parseMatchmakingRequest(appendClientRequestPadding(findWriter.Bytes(), 4), 4)
	if err != nil {
		t.Fatal(err)
	}
	if find.Task != MatchmakingTaskFind || find.NumParams != 1 || find.Offset != 0 || find.MaxResults != 50 ||
		find.Query != (MatchmakingQuery{AttributeHash: 0x11223344, AttributeValue: 1}) {
		t.Fatalf("find = %#v", find)
	}
}

func TestParseMatchmakingFindRejectsUnsupportedQueryShape(t *testing.T) {
	for _, test := range []struct {
		name       string
		numParams  uint32
		maxResults uint32
	}{
		{name: "no parameters", numParams: 0, maxResults: 1},
		{name: "multiple parameters", numParams: 2, maxResults: 1},
		{name: "too many results", numParams: 1, maxResults: maxFindResults + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := bitdemon.NewByteWriter(true)
			writer.WriteUint8(MatchmakingTaskFind)
			writer.WriteUint32(test.numParams)
			writer.WriteUint32(0)
			writer.WriteUint32(test.maxResults)
			writer.WriteUint32(21)
			writer.WriteInt32(1)
			if _, err := parseMatchmakingRequest(appendClientRequestPadding(writer.Bytes(), 1), 1); !errors.Is(err, ErrUnsupportedMatchmakingQuery) {
				t.Fatalf("parse error = %v, want %v", err, ErrUnsupportedMatchmakingQuery)
			}
		})
	}
}

func matchmakingFixture() MatchmakingInfo {
	return MatchmakingInfo{
		HostAddress: []byte{1, 2, 3, 4, 5},
		SessionID:   MatchmakingSessionID{8, 7, 6, 5, 4, 3, 2, 1},
		GameType:    11,
		MaxPlayers:  4,
		NumPlayers:  1,
		Attributes: MatchmakingAttributes{
			AppU32At11C:    21,
			AppU32At120:    1,
			AppU64At128:    23,
			AppStringAt130: "single-map",
			AppU32At154:    1,
			AppU32At158:    21,
			AppI32At15C:    1,
		},
	}
}

func writeMatchmakingRequestFixture(t *testing.T, writer *bitdemon.ByteWriter, info MatchmakingInfo) {
	t.Helper()
	if err := writer.WriteBlob(info.HostAddress); err != nil {
		t.Fatal(err)
	}
	writer.WriteUint32(info.GameType)
	writer.WriteUint32(info.MaxPlayers)
	writer.WriteUint32(info.Attributes.AppU32At11C)
	writer.WriteUint32(info.Attributes.AppU32At120)
	writer.WriteUint64(info.Attributes.AppU64At128)
	if err := writer.WriteString(info.Attributes.AppStringAt130); err != nil {
		t.Fatal(err)
	}
	writer.WriteUint32(info.Attributes.AppU32At154)
	writer.WriteUint32(info.Attributes.AppU32At158)
	writer.WriteInt32(info.Attributes.AppI32At15C)
}
