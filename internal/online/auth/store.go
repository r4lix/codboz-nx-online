package auth

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	DefaultMaxAccounts          = 4096
	DefaultMaxAccountsPerSource = 32
)

var (
	ErrAccountLimit         = errors.New("auth: account limit reached")
	ErrAccountSourceLimit   = errors.New("auth: account limit reached for source")
	ErrAccountHashCollision = errors.New("auth: account hash collision")
	ErrInvalidAccountSource = errors.New("auth: invalid account source")
)

type Account struct {
	UserID       uint64
	Username     string
	PasswordHash [accountPasswordSize]byte
	AccountHash  uint64
}

type MemoryAccountStore struct {
	mu                   sync.RWMutex
	maxAccounts          int
	maxAccountsPerSource int
	stateFile            string
	nextUserID           uint64
	byUsername           map[string]Account
	byHash               map[uint64]Account
	byUserID             map[uint64]Account
	accountsBySource     map[string]int
}

type MemoryAccountStoreConfig struct {
	MaxAccounts          int
	MaxAccountsPerSource int
	StateFile            string
}

func NewMemoryAccountStoreWithConfig(config MemoryAccountStoreConfig) (*MemoryAccountStore, error) {
	if config.MaxAccounts == 0 {
		config.MaxAccounts = DefaultMaxAccounts
	}
	if config.MaxAccountsPerSource == 0 {
		config.MaxAccountsPerSource = DefaultMaxAccountsPerSource
	}
	if config.MaxAccounts < 1 || config.MaxAccounts > 1_000_000 {
		return nil, errors.New("auth: maximum accounts must be between 1 and 1000000")
	}
	if config.MaxAccountsPerSource < 1 || config.MaxAccountsPerSource > 1_000_000 {
		return nil, errors.New("auth: maximum accounts per source must be between 1 and 1000000")
	}
	store := &MemoryAccountStore{
		maxAccounts:          config.MaxAccounts,
		maxAccountsPerSource: config.MaxAccountsPerSource,
		stateFile:            config.StateFile,
		nextUserID:           1,
		byUsername:           make(map[string]Account),
		byHash:               make(map[uint64]Account),
		byUserID:             make(map[uint64]Account),
		accountsBySource:     make(map[string]int),
	}
	if store.stateFile == "" {
		return store, nil
	}
	if err := ensureAccountFileDirectory(store.stateFile); err != nil {
		return nil, err
	}
	accounts, err := readAccountFile(store.stateFile, store.maxAccounts)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		store.byUsername[account.Username] = account
		store.byHash[account.AccountHash] = account
		store.byUserID[account.UserID] = account
		if account.UserID >= store.nextUserID {
			store.nextUserID = account.UserID + 1
			if store.nextUserID == 0 {
				return nil, errors.New("auth: persisted user ID space is exhausted")
			}
		}
	}
	return store, nil
}

func (store *MemoryAccountStore) Register(username string, passwordHash [accountPasswordSize]byte) (account Account, created bool, err error) {
	return store.register(username, passwordHash, "", false)
}

func (store *MemoryAccountStore) RegisterFromPeer(username string, passwordHash [accountPasswordSize]byte, peer net.Addr) (account Account, created bool, err error) {
	source, err := accountSourceIdentity(peer)
	if err != nil {
		return Account{}, false, err
	}
	return store.register(username, passwordHash, source, true)
}

func (store *MemoryAccountStore) register(username string, passwordHash [accountPasswordSize]byte, source string, enforceSourceLimit bool) (account Account, created bool, err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.byUsername[username]; ok {
		return existing, false, nil
	}
	if len(store.byUsername) >= store.maxAccounts {
		return Account{}, false, ErrAccountLimit
	}
	if enforceSourceLimit && store.accountsBySource[source] >= store.maxAccountsPerSource {
		return Account{}, false, ErrAccountSourceLimit
	}
	accountHash := BOZAccountHash(username)
	if existing, ok := store.byHash[accountHash]; ok {
		return existing, false, ErrAccountHashCollision
	}
	account = Account{
		UserID:       store.nextUserID,
		Username:     username,
		PasswordHash: passwordHash,
		AccountHash:  accountHash,
	}
	if store.stateFile != "" {
		accounts := make([]Account, 0, len(store.byUsername)+1)
		for _, existing := range store.byUsername {
			accounts = append(accounts, existing)
		}
		accounts = append(accounts, account)
		if err := writeAccountFile(store.stateFile, accounts); err != nil {
			return Account{}, false, err
		}
	}
	store.nextUserID++
	store.byUsername[username] = account
	store.byHash[accountHash] = account
	store.byUserID[account.UserID] = account
	if enforceSourceLimit {
		store.accountsBySource[source]++
	}
	return account, true, nil
}

func accountSourceIdentity(peer net.Addr) (string, error) {
	if peer == nil {
		return "", ErrInvalidAccountSource
	}
	var address netip.Addr
	if tcpPeer, ok := peer.(*net.TCPAddr); ok {
		var valid bool
		address, valid = netip.AddrFromSlice(tcpPeer.IP)
		if !valid {
			return "", ErrInvalidAccountSource
		}
	} else {
		host, _, err := net.SplitHostPort(peer.String())
		if err != nil {
			if peer.Network() == "" || peer.String() == "" {
				return "", ErrInvalidAccountSource
			}
			return peer.Network() + ":" + peer.String(), nil
		}
		address, err = netip.ParseAddr(host)
		if err != nil {
			return "", ErrInvalidAccountSource
		}
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return "", ErrInvalidAccountSource
	}
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String(), nil
	}
	return address.String(), nil
}

func (store *MemoryAccountStore) LookupHash(accountHash uint64) (Account, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	account, ok := store.byHash[accountHash]
	return account, ok
}

func (store *MemoryAccountStore) LookupUserID(userID uint64) (Account, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	account, ok := store.byUserID[userID]
	return account, ok
}

func BOZAccountHash(username string) uint64 {
	digest := bitdemon.Tiger192([]byte(strings.ToLower(username)))
	return binary.LittleEndian.Uint64(digest[0:8])
}

func (store *MemoryAccountStore) Lookup(username string) (Account, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	account, ok := store.byUsername[username]
	return account, ok
}
