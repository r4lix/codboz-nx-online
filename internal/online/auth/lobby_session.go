package auth

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	DefaultMaxLobbySessions           = 4096
	DefaultMaxLobbySessionsPerAccount = 4
)

var (
	ErrLobbySessionLimit         = errors.New("auth: pending lobby session limit reached")
	ErrLobbySessionAccountLimit  = errors.New("auth: pending lobby session limit reached for account")
	ErrLobbySessionSeedCollision = errors.New("auth: lobby session seed collision")
	ErrInvalidLobbySession       = errors.New("auth: invalid lobby session")
)

type LobbySession struct {
	TicketSeed  uint32
	UserID      uint64
	AccountHash uint64
	TitleID     uint32
	SessionKey  [bitdemon.SessionKeySize]byte
	ExpiresAt   time.Time
}

type pendingLobbySession struct {
	LobbySession
	peer  string
	token LobbySessionToken
}

type LobbySessionToken uint64

type MemoryLobbySessionStore struct {
	mu                    sync.Mutex
	maxSessions           int
	maxSessionsPerAccount int
	bySeed                map[uint32]pendingLobbySession
	sessionsByAccount     map[uint64]int
	nextToken             LobbySessionToken
}

type MemoryLobbySessionStoreConfig struct {
	MaxSessions           int
	MaxSessionsPerAccount int
}

func NewMemoryLobbySessionStoreWithConfig(config MemoryLobbySessionStoreConfig) (*MemoryLobbySessionStore, error) {
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxLobbySessions
	}
	if config.MaxSessionsPerAccount == 0 {
		config.MaxSessionsPerAccount = DefaultMaxLobbySessionsPerAccount
	}
	if config.MaxSessions < 1 || config.MaxSessions > 1_000_000 {
		return nil, errors.New("auth: maximum pending lobby sessions must be between 1 and 1000000")
	}
	if config.MaxSessionsPerAccount < 1 || config.MaxSessionsPerAccount > 1_000_000 {
		return nil, errors.New("auth: maximum pending lobby sessions per account must be between 1 and 1000000")
	}
	return &MemoryLobbySessionStore{
		maxSessions:           config.MaxSessions,
		maxSessionsPerAccount: config.MaxSessionsPerAccount,
		bySeed:                make(map[uint32]pendingLobbySession),
		sessionsByAccount:     make(map[uint64]int),
	}, nil
}

func (store *MemoryLobbySessionStore) Reserve(session LobbySession, peer net.Addr, now time.Time) (LobbySessionToken, error) {
	peerID, err := lobbyPeerIdentity(peer)
	if err != nil || session.UserID == 0 || session.TitleID != BOZTitleID || !session.ExpiresAt.After(now) {
		return 0, ErrInvalidLobbySession
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.purgeExpiredLocked(now)
	if _, exists := store.bySeed[session.TicketSeed]; exists {
		return 0, ErrLobbySessionSeedCollision
	}
	if store.sessionsByAccount[session.UserID] >= store.maxSessionsPerAccount {
		return 0, ErrLobbySessionAccountLimit
	}
	if len(store.bySeed) >= store.maxSessions {
		return 0, ErrLobbySessionLimit
	}
	store.nextToken++
	if store.nextToken == 0 {
		store.nextToken++
	}
	token := store.nextToken
	store.bySeed[session.TicketSeed] = pendingLobbySession{LobbySession: session, peer: peerID, token: token}
	store.sessionsByAccount[session.UserID]++
	return token, nil
}

func (store *MemoryLobbySessionStore) Lookup(ticketSeed uint32, peer net.Addr, now time.Time) (LobbySession, LobbySessionToken, bool) {
	peerID, err := lobbyPeerIdentity(peer)
	if err != nil {
		return LobbySession{}, 0, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.bySeed[ticketSeed]
	if !ok {
		return LobbySession{}, 0, false
	}
	if !pending.ExpiresAt.After(now) {
		store.deleteLocked(ticketSeed, pending)
		return LobbySession{}, 0, false
	}
	if pending.peer != peerID {
		return LobbySession{}, 0, false
	}
	return pending.LobbySession, pending.token, true
}

func (store *MemoryLobbySessionStore) Consume(ticketSeed uint32, token LobbySessionToken, peer net.Addr, now time.Time) (LobbySession, bool) {
	peerID, err := lobbyPeerIdentity(peer)
	if err != nil {
		return LobbySession{}, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.bySeed[ticketSeed]
	if !ok || pending.token != token {
		return LobbySession{}, false
	}
	if !pending.ExpiresAt.After(now) {
		store.deleteLocked(ticketSeed, pending)
		return LobbySession{}, false
	}
	if pending.peer != peerID {
		return LobbySession{}, false
	}
	store.deleteLocked(ticketSeed, pending)
	return pending.LobbySession, true
}

func (store *MemoryLobbySessionStore) Revoke(ticketSeed uint32, token LobbySessionToken) {
	store.mu.Lock()
	if pending, ok := store.bySeed[ticketSeed]; ok && pending.token == token {
		store.deleteLocked(ticketSeed, pending)
	}
	store.mu.Unlock()
}

func (store *MemoryLobbySessionStore) purgeExpiredLocked(now time.Time) {
	for seed, pending := range store.bySeed {
		if !pending.ExpiresAt.After(now) {
			store.deleteLocked(seed, pending)
		}
	}
}

func (store *MemoryLobbySessionStore) deleteLocked(seed uint32, pending pendingLobbySession) {
	delete(store.bySeed, seed)
	remaining := store.sessionsByAccount[pending.UserID] - 1
	if remaining <= 0 {
		delete(store.sessionsByAccount, pending.UserID)
		return
	}
	store.sessionsByAccount[pending.UserID] = remaining
}

func lobbyPeerIdentity(peer net.Addr) (string, error) {
	if peer == nil {
		return "", ErrInvalidLobbySession
	}
	if tcpPeer, ok := peer.(*net.TCPAddr); ok {
		address, ok := netip.AddrFromSlice(tcpPeer.IP)
		if !ok || !address.IsValid() {
			return "", ErrInvalidLobbySession
		}
		return address.Unmap().String(), nil
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err == nil {
		address, parseErr := netip.ParseAddr(host)
		if parseErr == nil {
			return address.Unmap().String(), nil
		}
		return host, nil
	}
	if peer.Network() == "" || peer.String() == "" {
		return "", ErrInvalidLobbySession
	}
	return peer.Network() + ":" + peer.String(), nil
}
