package lobby

import (
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
)

const (
	DefaultMaxMatchmakingSessions         = 4096
	DefaultMaxMatchmakingSessionsPerOwner = 4
	maxSessionIDAttempts                  = 16
)

var (
	ErrMatchmakingSessionLimit      = errors.New("lobby: matchmaking session limit reached")
	ErrMatchmakingOwnerSessionLimit = errors.New("lobby: matchmaking session limit reached for owner")
	ErrMatchmakingSessionID         = errors.New("lobby: could not allocate matchmaking session ID")
	ErrMatchmakingSessionOwner      = errors.New("lobby: matchmaking session is not owned by this connection")
	ErrMatchmakingSessionMiss       = errors.New("lobby: matchmaking session does not exist")
)

type storedMatchmakingSession struct {
	info  MatchmakingInfo
	owner uint64
	order uint64
}

type MemoryMatchmakingStore struct {
	mu                  sync.RWMutex
	maxSessions         int
	maxSessionsPerOwner int
	nextOrder           uint64
	byID                map[MatchmakingSessionID]storedMatchmakingSession
	sessionsByOwner     map[uint64]int
}

type MemoryMatchmakingStoreConfig struct {
	MaxSessions         int
	MaxSessionsPerOwner int
}

func NewMemoryMatchmakingStoreWithConfig(config MemoryMatchmakingStoreConfig) (*MemoryMatchmakingStore, error) {
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxMatchmakingSessions
	}
	if config.MaxSessionsPerOwner == 0 {
		config.MaxSessionsPerOwner = DefaultMaxMatchmakingSessionsPerOwner
	}
	if config.MaxSessions < 1 || config.MaxSessions > 1_000_000 {
		return nil, errors.New("lobby: maximum matchmaking sessions must be between 1 and 1000000")
	}
	if config.MaxSessionsPerOwner < 1 || config.MaxSessionsPerOwner > 1_000_000 {
		return nil, errors.New("lobby: maximum matchmaking sessions per owner must be between 1 and 1000000")
	}
	return &MemoryMatchmakingStore{
		maxSessions:         config.MaxSessions,
		maxSessionsPerOwner: config.MaxSessionsPerOwner,
		byID:                make(map[MatchmakingSessionID]storedMatchmakingSession),
		sessionsByOwner:     make(map[uint64]int),
	}, nil
}

func (store *MemoryMatchmakingStore) Create(owner uint64, requested MatchmakingInfo, random io.Reader) (MatchmakingInfo, error) {
	if owner == 0 || random == nil || !validStoredMatchmakingInfo(requested) {
		return MatchmakingInfo{}, ErrMalformedMatchmakingRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.byID) >= store.maxSessions {
		return MatchmakingInfo{}, ErrMatchmakingSessionLimit
	}
	if store.sessionsByOwner[owner] >= store.maxSessionsPerOwner {
		return MatchmakingInfo{}, ErrMatchmakingOwnerSessionLimit
	}
	for attempt := 0; attempt < maxSessionIDAttempts; attempt++ {
		var sessionID MatchmakingSessionID
		if _, err := io.ReadFull(random, sessionID[:]); err != nil {
			return MatchmakingInfo{}, err
		}
		if allZero(sessionID[:]) {
			continue
		}
		if _, exists := store.byID[sessionID]; exists {
			continue
		}
		created := cloneMatchmakingInfo(requested)
		created.SessionID = sessionID
		created.NumPlayers = 1
		store.nextOrder++
		store.byID[sessionID] = storedMatchmakingSession{info: created, owner: owner, order: store.nextOrder}
		store.sessionsByOwner[owner]++
		return cloneMatchmakingInfo(created), nil
	}
	return MatchmakingInfo{}, ErrMatchmakingSessionID
}

func (store *MemoryMatchmakingStore) Update(owner uint64, sessionID MatchmakingSessionID, requested MatchmakingInfo) error {
	if owner == 0 || !validStoredMatchmakingInfo(requested) {
		return ErrMalformedMatchmakingRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, ok := store.byID[sessionID]
	if !ok {
		return ErrMatchmakingSessionMiss
	}
	if existing.owner != owner {
		return ErrMatchmakingSessionOwner
	}
	updated := cloneMatchmakingInfo(requested)
	updated.SessionID = sessionID
	updated.NumPlayers = existing.info.NumPlayers
	existing.info = updated
	store.byID[sessionID] = existing
	return nil
}

func (store *MemoryMatchmakingStore) Delete(owner uint64, sessionID MatchmakingSessionID) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, ok := store.byID[sessionID]
	if !ok {
		return ErrMatchmakingSessionMiss
	}
	if existing.owner != owner {
		return ErrMatchmakingSessionOwner
	}
	store.deleteLocked(sessionID, existing)
	return nil
}

func (store *MemoryMatchmakingStore) Find(query MatchmakingQuery, offset, maximum uint32) ([]MatchmakingInfo, uint32) {
	store.mu.RLock()
	sessions := make([]storedMatchmakingSession, 0, len(store.byID))
	for _, session := range store.byID {
		if matchesQuery(session.info, query) {
			sessions = append(sessions, session)
		}
	}
	store.mu.RUnlock()
	sort.Slice(sessions, func(left, right int) bool { return sessions[left].order < sessions[right].order })
	total := uint32(len(sessions))
	if offset >= total || maximum == 0 {
		return nil, total
	}
	end := uint64(offset) + uint64(maximum)
	if end > uint64(total) {
		end = uint64(total)
	}
	result := make([]MatchmakingInfo, 0, end-uint64(offset))
	for _, session := range sessions[offset:end] {
		result = append(result, cloneMatchmakingInfo(session.info))
	}
	return result, total
}

func matchesQuery(info MatchmakingInfo, query MatchmakingQuery) bool {
	return query.Key == matchmakingFindQueryKey &&
		info.Attributes.AppI32At15C == query.Value
}

func (store *MemoryMatchmakingStore) DeleteOwner(owner uint64) {
	store.mu.Lock()
	for sessionID, session := range store.byID {
		if session.owner == owner {
			store.deleteLocked(sessionID, session)
		}
	}
	store.mu.Unlock()
}

func (store *MemoryMatchmakingStore) deleteLocked(sessionID MatchmakingSessionID, session storedMatchmakingSession) {
	delete(store.byID, sessionID)
	remaining := store.sessionsByOwner[session.owner] - 1
	if remaining <= 0 {
		delete(store.sessionsByOwner, session.owner)
		return
	}
	store.sessionsByOwner[session.owner] = remaining
}

func cloneMatchmakingInfo(info MatchmakingInfo) MatchmakingInfo {
	info.HostAddress = append([]byte(nil), info.HostAddress...)
	return info
}

func validStoredMatchmakingInfo(info MatchmakingInfo) bool {
	return len(info.HostAddress) <= maxHostAddressSize &&
		info.MaxPlayers != 0 &&
		len(info.Attributes.AppStringAt130) <= maxMatchmakingTextBytes &&
		strings.IndexByte(info.Attributes.AppStringAt130, 0) < 0
}
