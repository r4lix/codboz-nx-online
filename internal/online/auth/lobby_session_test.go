package auth

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestMemoryLobbySessionStoreBindsAndConsumesSession(t *testing.T) {
	store, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	session := LobbySession{
		TicketSeed:  0x12345678,
		UserID:      7,
		AccountHash: 9,
		TitleID:     BOZTitleID,
		ExpiresAt:   now.Add(time.Minute),
	}
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	token, err := store.Reserve(session, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(session, peer, now); !errors.Is(err, ErrLobbySessionSeedCollision) {
		t.Fatalf("duplicate Reserve() error = %v, want %v", err, ErrLobbySessionSeedCollision)
	}
	wrongPeer := &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 30000}
	if _, _, ok := store.Lookup(session.TicketSeed, wrongPeer, now); ok {
		t.Fatal("session found from the wrong peer")
	}
	differentPort := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 31000}
	got, foundToken, ok := store.Lookup(session.TicketSeed, differentPort, now)
	if !ok || got != session || foundToken != token {
		t.Fatalf("Lookup() = %#v, %d, %t, want %#v, %d, true", got, foundToken, ok, session, token)
	}
	if _, ok := store.Consume(session.TicketSeed, token+1, differentPort, now); ok {
		t.Fatal("session consumed with the wrong generation token")
	}
	got, ok = store.Consume(session.TicketSeed, token, differentPort, now)
	if !ok || got != session {
		t.Fatalf("Consume() = %#v, %t, want %#v, true", got, ok, session)
	}
	if _, ok := store.Consume(session.TicketSeed, token, peer, now); ok {
		t.Fatal("session was consumed more than once")
	}
}

func TestMemoryLobbySessionStoreExpiresAndReclaimsCapacity(t *testing.T) {
	store, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	expiredSoon := LobbySession{TicketSeed: 1, UserID: 1, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Second)}
	if _, err := store.Reserve(expiredSoon, peer, now); err != nil {
		t.Fatal(err)
	}
	replacement := LobbySession{TicketSeed: 2, UserID: 2, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.Reserve(replacement, peer, now.Add(2*time.Second)); err != nil {
		t.Fatalf("Reserve() after expiry: %v", err)
	}
	if _, _, ok := store.Lookup(expiredSoon.TicketSeed, peer, now.Add(2*time.Second)); ok {
		t.Fatal("expired session remained consumable")
	}
}

func TestMemoryLobbySessionStoreRevokeIsGenerationFenced(t *testing.T) {
	store, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	first := LobbySession{TicketSeed: 7, UserID: 1, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	firstToken, err := store.Reserve(first, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Consume(first.TicketSeed, firstToken, peer, now); !ok {
		t.Fatal("first session was not consumed")
	}
	second := LobbySession{TicketSeed: 7, UserID: 2, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	secondToken, err := store.Reserve(second, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	store.Revoke(first.TicketSeed, firstToken)
	got, gotToken, ok := store.Lookup(second.TicketSeed, peer, now)
	if !ok || got != second || gotToken != secondToken {
		t.Fatalf("new generation after stale revoke = %#v, %d, %t", got, gotToken, ok)
	}
}

func TestMemoryLobbySessionStoreEnforcesPerAccountLimitAndReleasesIt(t *testing.T) {
	store, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{
		MaxSessions:           3,
		MaxSessionsPerAccount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	first := LobbySession{TicketSeed: 1, UserID: 10, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	firstToken, err := store.Reserve(first, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	secondForAccount := LobbySession{TicketSeed: 2, UserID: 10, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.Reserve(secondForAccount, peer, now); !errors.Is(err, ErrLobbySessionAccountLimit) {
		t.Fatalf("same-account Reserve() error = %v, want %v", err, ErrLobbySessionAccountLimit)
	}
	otherAccount := LobbySession{TicketSeed: 3, UserID: 11, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.Reserve(otherAccount, peer, now); err != nil {
		t.Fatalf("other-account Reserve(): %v", err)
	}
	store.Revoke(first.TicketSeed, firstToken)
	if _, err := store.Reserve(secondForAccount, peer, now); err != nil {
		t.Fatalf("Reserve() after revoke: %v", err)
	}
}

func TestMemoryLobbySessionStoreExpiryReleasesPerAccountLimit(t *testing.T) {
	store, err := NewMemoryLobbySessionStoreWithConfig(MemoryLobbySessionStoreConfig{
		MaxSessions:           2,
		MaxSessionsPerAccount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	expiring := LobbySession{TicketSeed: 1, UserID: 10, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Second)}
	if _, err := store.Reserve(expiring, peer, now); err != nil {
		t.Fatal(err)
	}
	replacement := LobbySession{TicketSeed: 2, UserID: 10, TitleID: BOZTitleID, ExpiresAt: now.Add(time.Minute)}
	if _, err := store.Reserve(replacement, peer, now.Add(2*time.Second)); err != nil {
		t.Fatalf("Reserve() after account session expiry: %v", err)
	}
}
