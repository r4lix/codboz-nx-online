package auth

import (
	"errors"
	"net"
	"testing"
)

func TestMemoryAccountStoreRegistrationIsIdempotent(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{MaxAccounts: 2})
	if err != nil {
		t.Fatal(err)
	}
	firstHash := [accountPasswordSize]byte{1, 2, 3}
	first, created, err := store.Register("GEN__fixture", firstHash)
	if err != nil || !created {
		t.Fatalf("first Register() = %#v, %t, %v", first, created, err)
	}
	second, created, err := store.Register("GEN__fixture", [accountPasswordSize]byte{9})
	if err != nil || created {
		t.Fatalf("second Register() = %#v, %t, %v", second, created, err)
	}
	if second != first {
		t.Fatalf("idempotent account = %#v, want %#v", second, first)
	}
	if lookedUp, ok := store.Lookup("GEN__fixture"); !ok || lookedUp != first {
		t.Fatalf("Lookup() = %#v, %t", lookedUp, ok)
	}
	if lookedUp, ok := store.LookupHash(BOZAccountHash("gen__FIXTURE")); !ok || lookedUp != first {
		t.Fatalf("LookupHash() = %#v, %t", lookedUp, ok)
	}
	if lookedUp, ok := store.LookupUserID(first.UserID); !ok || lookedUp != first {
		t.Fatalf("LookupUserID() = %#v, %t", lookedUp, ok)
	}
}

func TestMemoryAccountStoreEnforcesLimit(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{MaxAccounts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Register("first", [accountPasswordSize]byte{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Register("second", [accountPasswordSize]byte{}); !errors.Is(err, ErrAccountLimit) {
		t.Fatalf("Register() error = %v, want %v", err, ErrAccountLimit)
	}
}

func TestMemoryAccountStoreEnforcesPerSourceLimit(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{
		MaxAccounts:          3,
		MaxAccountsPerSource: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstSource := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	first, created, err := store.RegisterFromPeer("first", [accountPasswordSize]byte{1}, firstSource)
	if err != nil || !created {
		t.Fatalf("first RegisterFromPeer() = %#v, %t, %v", first, created, err)
	}
	if retry, created, err := store.RegisterFromPeer("first", [accountPasswordSize]byte{2}, firstSource); err != nil || created || retry != first {
		t.Fatalf("idempotent RegisterFromPeer() = %#v, %t, %v", retry, created, err)
	}
	if _, _, err := store.RegisterFromPeer("second", [accountPasswordSize]byte{}, firstSource); !errors.Is(err, ErrAccountSourceLimit) {
		t.Fatalf("same-source RegisterFromPeer() error = %v, want %v", err, ErrAccountSourceLimit)
	}
	secondSource := &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 30000}
	if _, created, err := store.RegisterFromPeer("second", [accountPasswordSize]byte{}, secondSource); err != nil || !created {
		t.Fatalf("other-source RegisterFromPeer() = created %t, error %v", created, err)
	}
}

func TestMemoryAccountStoreGroupsIPv6SourcesByPrefix(t *testing.T) {
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{
		MaxAccounts:          2,
		MaxAccountsPerSource: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := &net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 30000}
	second := &net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 30001}
	if _, _, err := store.RegisterFromPeer("first", [accountPasswordSize]byte{}, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterFromPeer("second", [accountPasswordSize]byte{}, second); !errors.Is(err, ErrAccountSourceLimit) {
		t.Fatalf("same-/64 RegisterFromPeer() error = %v, want %v", err, ErrAccountSourceLimit)
	}
}
