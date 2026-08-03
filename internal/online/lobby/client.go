package lobby

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Producdevity/cod-boz-online/internal/online/auth"
	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

type lobbyClient struct {
	connection     net.Conn
	writeTimeout   time.Duration
	account        auth.Account
	sessionKey     [bitdemon.SessionKeySize]byte
	writeMu        sync.Mutex
	nextServerSeed atomic.Uint32
}

func (client *lobbyClient) writeFrame(body []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if err := client.connection.SetWriteDeadline(time.Now().Add(client.writeTimeout)); err != nil {
		return err
	}
	return bitdemon.WriteFrame(client.connection, body)
}

func (client *lobbyClient) serverSeed() uint32 {
	return client.nextServerSeed.Add(1) - 1
}

type activeLobbyClients struct {
	mu        sync.RWMutex
	byAccount map[uint64]*lobbyClient
}

func newActiveLobbyClients() *activeLobbyClients {
	return &activeLobbyClients{byAccount: make(map[uint64]*lobbyClient)}
}

func (clients *activeLobbyClients) activate(client *lobbyClient) {
	clients.mu.Lock()
	previous := clients.byAccount[client.account.AccountHash]
	clients.byAccount[client.account.AccountHash] = client
	clients.mu.Unlock()
	if previous != nil && previous != client {
		_ = previous.connection.Close()
	}
}

func (clients *activeLobbyClients) deactivate(client *lobbyClient) {
	clients.mu.Lock()
	if clients.byAccount[client.account.AccountHash] == client {
		delete(clients.byAccount, client.account.AccountHash)
	}
	clients.mu.Unlock()
}

func (clients *activeLobbyClients) lookup(accountHash uint64) *lobbyClient {
	clients.mu.RLock()
	client := clients.byAccount[accountHash]
	clients.mu.RUnlock()
	return client
}
