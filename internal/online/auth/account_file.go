package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	accountFileVersion  = 1
	maxAccountFileBytes = 16 << 20
)

type accountFile struct {
	Version  int                `json:"version"`
	Accounts []persistedAccount `json:"accounts"`
}

type persistedAccount struct {
	UserID       uint64 `json:"user_id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

func ensureAccountFileDirectory(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("auth: create account data directory: %w", err)
	}
	return nil
}

func readAccountFile(path string, maximum int) ([]Account, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: open account file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("auth: inspect account file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("auth: account file must be a regular file")
	}
	if info.Size() > maxAccountFileBytes {
		return nil, fmt.Errorf("auth: account file exceeds %d bytes", maxAccountFileBytes)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("auth: account file permissions must not allow group or other access")
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var stored accountFile
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("auth: decode account file: %w", err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return nil, err
	}
	if stored.Version != accountFileVersion {
		return nil, fmt.Errorf("auth: unsupported account file version %d", stored.Version)
	}
	if len(stored.Accounts) > maximum {
		return nil, fmt.Errorf("auth: account file contains %d accounts, limit is %d", len(stored.Accounts), maximum)
	}

	accounts := make([]Account, 0, len(stored.Accounts))
	userIDs := make(map[uint64]struct{}, len(stored.Accounts))
	usernames := make(map[string]struct{}, len(stored.Accounts))
	hashes := make(map[uint64]struct{}, len(stored.Accounts))
	for _, persisted := range stored.Accounts {
		account, err := decodePersistedAccount(persisted)
		if err != nil {
			return nil, err
		}
		if _, duplicate := userIDs[account.UserID]; duplicate {
			return nil, fmt.Errorf("auth: duplicate persisted user ID %d", account.UserID)
		}
		if _, duplicate := usernames[account.Username]; duplicate {
			return nil, fmt.Errorf("auth: duplicate persisted username %q", account.Username)
		}
		if _, duplicate := hashes[account.AccountHash]; duplicate {
			return nil, fmt.Errorf("auth: duplicate persisted account hash %016x", account.AccountHash)
		}
		userIDs[account.UserID] = struct{}{}
		usernames[account.Username] = struct{}{}
		hashes[account.AccountHash] = struct{}{}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("auth: account file contains multiple JSON values")
		}
		return fmt.Errorf("auth: decode account file trailer: %w", err)
	}
	return nil
}

func decodePersistedAccount(persisted persistedAccount) (Account, error) {
	if persisted.UserID == 0 {
		return Account{}, errors.New("auth: persisted user ID must not be zero")
	}
	var usernameField [accountUsernameSize]byte
	if len(persisted.Username) == 0 || len(persisted.Username) > len(usernameField) {
		return Account{}, fmt.Errorf("auth: invalid persisted username %q", persisted.Username)
	}
	copy(usernameField[:], persisted.Username)
	username, err := parsePaddedUsername(usernameField[:])
	if err != nil || username != persisted.Username {
		return Account{}, fmt.Errorf("auth: invalid persisted username %q", persisted.Username)
	}
	passwordBytes, err := hex.DecodeString(persisted.PasswordHash)
	if err != nil || len(passwordBytes) != bitdemon.SessionKeySize {
		return Account{}, errors.New("auth: invalid persisted password hash")
	}
	account := Account{
		UserID:      persisted.UserID,
		Username:    username,
		AccountHash: BOZAccountHash(username),
	}
	copy(account.PasswordHash[:], passwordBytes)
	return account, nil
}

func writeAccountFile(path string, accounts []Account) error {
	stored := accountFile{Version: accountFileVersion, Accounts: make([]persistedAccount, 0, len(accounts))}
	ordered := append([]Account(nil), accounts...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].UserID < ordered[right].UserID })
	for _, account := range ordered {
		stored.Accounts = append(stored.Accounts, persistedAccount{
			UserID:       account.UserID,
			Username:     account.Username,
			PasswordHash: hex.EncodeToString(account.PasswordHash[:]),
		})
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".accounts-*.tmp")
	if err != nil {
		return fmt.Errorf("auth: create temporary account file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("auth: restrict temporary account file: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(stored); err != nil {
		return fmt.Errorf("auth: encode account file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("auth: sync account file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("auth: close account file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("auth: replace account file: %w", err)
	}
	committed = true

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("auth: open account data directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("auth: sync account data directory: %w", err)
	}
	return nil
}
