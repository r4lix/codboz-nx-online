package lobby

import (
	"bytes"
	"errors"
	"testing"
)

func TestMemoryMatchmakingStoreLifecycleAndOwnership(t *testing.T) {
	store, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewReader([]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
	})
	first, err := store.Create(10, matchmakingFixture(), random)
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionID != (MatchmakingSessionID{1, 2, 3, 4, 5, 6, 7, 8}) || first.NumPlayers != 1 {
		t.Fatalf("first session = %#v", first)
	}
	secondRequest := matchmakingFixture()
	secondRequest.HostAddress[0] = 9
	secondRequest.Attributes.AppU32At11C = 22
	secondRequest.Attributes.AppU32At158 = 22
	second, err := store.Create(20, secondRequest, random)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(20, first.SessionID, matchmakingFixture()); !errors.Is(err, ErrMatchmakingSessionOwner) {
		t.Fatalf("foreign Update() error = %v, want %v", err, ErrMatchmakingSessionOwner)
	}
	updated := matchmakingFixture()
	updated.HostAddress = []byte{42, 43}
	if err := store.Update(10, first.SessionID, updated); err != nil {
		t.Fatal(err)
	}
	query := MatchmakingQuery{Key: 21, Value: 1}
	page, total := store.Find(query, 0, 1)
	if total != 1 || len(page) != 1 || page[0].SessionID != first.SessionID || !bytes.Equal(page[0].HostAddress, updated.HostAddress) {
		t.Fatalf("first page = %#v, total=%d", page, total)
	}
	if results, total := store.Find(MatchmakingQuery{Key: 21, Value: 2}, 0, 2); len(results) != 0 || total != 0 {
		t.Fatalf("mismatched query value returned %#v, total=%d", results, total)
	}
	if results, total := store.Find(MatchmakingQuery{Key: 23, Value: 1}, 0, 2); len(results) != 0 || total != 0 {
		t.Fatalf("unknown query key returned %#v, total=%d", results, total)
	}
	wildcard, total := store.Find(MatchmakingQuery{Key: matchmakingWildcardKey, Value: 1}, 0, 2)
	if len(wildcard) != 2 || total != 2 {
		t.Fatalf("wildcard query returned %#v, total=%d", wildcard, total)
	}
	page[0].HostAddress[0] = 0
	again, _ := store.Find(query, 0, 1)
	if again[0].HostAddress[0] != 42 {
		t.Fatal("Find() exposed mutable host address storage")
	}
	store.DeleteOwner(10)
	remaining, total := store.Find(MatchmakingQuery{Key: 22, Value: 1}, 0, 2)
	if total != 1 || len(remaining) != 1 || remaining[0].SessionID != second.SessionID {
		t.Fatalf("remaining sessions = %#v, total=%d", remaining, total)
	}
	if err := store.Delete(20, second.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, total := store.Find(query, 0, 2); total != 0 {
		t.Fatalf("total after delete = %d, want 0", total)
	}
}

func TestMemoryMatchmakingStoreEnforcesPerOwnerLimitAndReleasesIt(t *testing.T) {
	store, err := NewMemoryMatchmakingStoreWithConfig(MemoryMatchmakingStoreConfig{
		MaxSessions:         3,
		MaxSessionsPerOwner: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewReader([]byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
	})
	first, err := store.Create(10, matchmakingFixture(), random)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(10, matchmakingFixture(), random); !errors.Is(err, ErrMatchmakingOwnerSessionLimit) {
		t.Fatalf("same-owner Create() error = %v, want %v", err, ErrMatchmakingOwnerSessionLimit)
	}
	if _, err := store.Create(20, matchmakingFixture(), random); err != nil {
		t.Fatalf("other-owner Create(): %v", err)
	}
	if err := store.Delete(10, first.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(10, matchmakingFixture(), random); err != nil {
		t.Fatalf("Create() after delete: %v", err)
	}
	store.DeleteOwner(10)
	if _, err := store.Create(10, matchmakingFixture(), bytes.NewReader([]byte{25, 26, 27, 28, 29, 30, 31, 32})); err != nil {
		t.Fatalf("Create() after owner cleanup: %v", err)
	}
}
