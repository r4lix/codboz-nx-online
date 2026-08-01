package auth

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentAccountStoreSurvivesRestart(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state", "accounts.json")
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{
		MaxAccounts: 4,
		StateFile:   stateFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	password := [accountPasswordSize]byte{1, 2, 3, 4}
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000}
	created, wasCreated, err := store.RegisterFromPeer("GEN__persistent", password, peer)
	if err != nil || !wasCreated {
		t.Fatalf("RegisterFromPeer() = %#v, %t, %v", created, wasCreated, err)
	}

	info, err := os.Stat(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("account file permissions = %o, want 600", permissions)
	}

	reopened, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{
		MaxAccounts: 4,
		StateFile:   stateFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reopened.Lookup("GEN__persistent")
	if !ok || loaded != created {
		t.Fatalf("loaded account = %#v, %t; want %#v", loaded, ok, created)
	}
	if retry, retryCreated, err := reopened.Register("GEN__persistent", [accountPasswordSize]byte{9}); err != nil || retryCreated || retry != created {
		t.Fatalf("idempotent retry = %#v, %t, %v", retry, retryCreated, err)
	}
	next, nextCreated, err := reopened.Register("GEN__next", [accountPasswordSize]byte{5})
	if err != nil || !nextCreated || next.UserID != created.UserID+1 {
		t.Fatalf("next account = %#v, %t, %v", next, nextCreated, err)
	}
}

func TestPersistentAccountStoreRejectsUnsafeOrMalformedState(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		mode     os.FileMode
		want     string
	}{
		{name: "permissions", contents: `{"version":1,"accounts":[]}`, mode: 0o644, want: "permissions"},
		{name: "version", contents: `{"version":2,"accounts":[]}`, mode: 0o600, want: "version"},
		{name: "unknown field", contents: `{"version":1,"accounts":[],"extra":true}`, mode: 0o600, want: "unknown field"},
		{name: "trailer", contents: `{"version":1,"accounts":[]} {}`, mode: 0o600, want: "multiple JSON"},
		{name: "bad password", contents: `{"version":1,"accounts":[{"user_id":1,"username":"GEN__bad","password_hash":"00"}]}`, mode: 0o600, want: "password hash"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateFile := filepath.Join(t.TempDir(), "accounts.json")
			if err := os.WriteFile(stateFile, []byte(test.contents), test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stateFile, test.mode); err != nil {
				t.Fatal(err)
			}
			_, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{StateFile: stateFile})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("constructor error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPersistentAccountStoreRejectsOversizedState(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "accounts.json")
	file, err := os.OpenFile(stateFile, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxAccountFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{StateFile: stateFile}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("constructor error = %v, want oversized-file rejection", err)
	}
}

func TestPersistentAccountStoreRollsBackFailedWrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	stateFile := filepath.Join(directory, "accounts.json")
	store, err := NewMemoryAccountStoreWithConfig(MemoryAccountStoreConfig{StateFile: stateFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.Register("GEN__rollback", [accountPasswordSize]byte{1}); err == nil || created {
		t.Fatalf("Register() = created %t, error %v; want failed write", created, err)
	}
	if _, ok := store.Lookup("GEN__rollback"); ok {
		t.Fatal("failed persistent registration remained in memory")
	}
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	account, created, err := store.Register("GEN__rollback", [accountPasswordSize]byte{1})
	if err != nil || !created || account.UserID != 1 {
		t.Fatalf("retry = %#v, %t, %v", account, created, err)
	}
}
