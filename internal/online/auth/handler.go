package auth

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	DefaultMaxRecords       = 16
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultWriteTimeout     = 5 * time.Second
	DefaultSessionLife      = time.Hour
	maxSeedAttempts         = 16

	StatusCreateMaxAccountsExceeded Status = 710
)

var (
	ErrRecordLimit            = errors.New("auth: transport record limit reached")
	ErrUnsupportedAuthMessage = errors.New("auth: unsupported authentication message")
)

type HandlerConfig struct {
	MaxRecords       int
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration
	SessionLife      time.Duration
	Random           io.Reader
	Now              func() time.Time
}

type Handler struct {
	config   HandlerConfig
	accounts *MemoryAccountStore
	sessions *MemoryLobbySessionStore
}

func NewHandler(config HandlerConfig, accounts *MemoryAccountStore, sessions *MemoryLobbySessionStore) (*Handler, error) {
	if accounts == nil || sessions == nil {
		return nil, errors.New("auth: account and lobby session stores are required")
	}
	if config.MaxRecords == 0 {
		config.MaxRecords = DefaultMaxRecords
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = DefaultWriteTimeout
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if config.SessionLife == 0 {
		config.SessionLife = DefaultSessionLife
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxRecords < 1 || config.MaxRecords > 1024 {
		return nil, errors.New("auth: maximum records must be between 1 and 1024")
	}
	if config.WriteTimeout < time.Second || config.WriteTimeout > time.Minute {
		return nil, errors.New("auth: write timeout must be between 1s and 1m")
	}
	if config.HandshakeTimeout < time.Second || config.HandshakeTimeout > 5*time.Minute {
		return nil, errors.New("auth: handshake timeout must be between 1s and 5m")
	}
	if config.SessionLife < time.Minute || config.SessionLife > 24*time.Hour {
		return nil, errors.New("auth: session lifetime must be between 1m and 24h")
	}
	return &Handler{config: config, accounts: accounts, sessions: sessions}, nil
}

// HandleTCP serves account creation and matchmaking-ticket requests.
func (handler *Handler) HandleTCP(ctx context.Context, connection net.Conn) error {
	if err := connection.SetReadDeadline(time.Now().Add(handler.config.HandshakeTimeout)); err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	}
	for recordIndex := 0; recordIndex < handler.config.MaxRecords; recordIndex++ {
		if ctx.Err() != nil {
			return nil
		}
		record, err := bitdemon.ReadTransportRecord(connection, bitdemon.DefaultMaxFrameBody)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				return nil
			}
			return err
		}

		switch record.Kind {
		case bitdemon.RecordKindKeepalive:
			if err := handler.writeFrame(connection, nil); err != nil {
				return err
			}
		case bitdemon.RecordKindBufferAvailable:
			continue
		case bitdemon.RecordKindFrame:
			if len(record.Body) < 2 {
				return fmt.Errorf("%w: missing message type", ErrUnsupportedAuthMessage)
			}
			switch record.Body[1] {
			case MessageCreateAccountRequest:
				if err := handler.handleCreateAccount(connection, record.Body); err != nil {
					return err
				}
			case MessageAccountForMMPRequest:
				if err := handler.handleAccountForMMP(connection, record.Body); err != nil {
					return err
				}
			default:
				messageType := byte(0xff)
				if len(record.Body) >= 2 {
					messageType = record.Body[1]
				}
				return fmt.Errorf("%w: 0x%02x", ErrUnsupportedAuthMessage, messageType)
			}
		default:
			return errors.New("auth: unknown transport record kind")
		}
	}
	return ErrRecordLimit
}

func (handler *Handler) handleCreateAccount(connection net.Conn, body []byte) error {
	request, err := ParseCreateAccountBody(body)
	if err != nil {
		return err
	}
	_, created, err := handler.accounts.RegisterFromPeer(request.Username, request.PasswordHash, connection.RemoteAddr())
	status := StatusCreateUsernameExists
	if err == nil && created {
		status = StatusNoError
	} else if errors.Is(err, ErrAccountLimit) || errors.Is(err, ErrAccountSourceLimit) {
		status = StatusCreateMaxAccountsExceeded
	} else if err != nil {
		return err
	}
	return handler.writeFrame(connection, MarshalCreateAccountReplyBody(status))
}

func (handler *Handler) handleAccountForMMP(connection net.Conn, body []byte) error {
	request, err := ParseAccountForMMPBody(body)
	if err != nil {
		return err
	}
	account, ok := handler.accounts.LookupHash(request.AccountHash)
	if !ok {
		return handler.writeFrame(connection, marshalAccountForMMPErrorBody(StatusBadAccount))
	}
	var sessionKey [bitdemon.SessionKeySize]byte
	if _, err := io.ReadFull(handler.config.Random, sessionKey[:]); err != nil {
		return fmt.Errorf("auth: generate session key: %w", err)
	}
	issuedAt := handler.config.Now().UTC()
	expiresAt := issuedAt.Add(handler.config.SessionLife)
	var ticketSeed uint32
	var sessionToken LobbySessionToken
	reserved := false
	for attempt := 0; attempt < maxSeedAttempts; attempt++ {
		var encodedSeed [4]byte
		if _, err := io.ReadFull(handler.config.Random, encodedSeed[:]); err != nil {
			return fmt.Errorf("auth: generate ticket seed: %w", err)
		}
		ticketSeed = binary.LittleEndian.Uint32(encodedSeed[:])
		token, err := handler.sessions.Reserve(LobbySession{
			TicketSeed:  ticketSeed,
			UserID:      account.UserID,
			TitleID:     BOZTitleID,
			AccountHash: account.AccountHash,
			SessionKey:  sessionKey,
			ExpiresAt:   expiresAt,
		}, connection.RemoteAddr(), issuedAt)
		if errors.Is(err, ErrLobbySessionSeedCollision) {
			continue
		}
		if err != nil {
			return err
		}
		sessionToken = token
		reserved = true
		break
	}
	if !reserved {
		return ErrLobbySessionSeedCollision
	}
	reply, err := marshalAccountForMMPSuccessBody(account, ticketSeed, sessionKey, issuedAt, expiresAt)
	if err != nil {
		handler.sessions.Revoke(ticketSeed, sessionToken)
		return err
	}
	if err := handler.writeFrame(connection, reply); err != nil {
		handler.sessions.Revoke(ticketSeed, sessionToken)
		return err
	}
	return nil
}

func (handler *Handler) writeFrame(connection net.Conn, body []byte) error {
	if err := connection.SetWriteDeadline(time.Now().Add(handler.config.WriteTimeout)); err != nil {
		return err
	}
	return bitdemon.WriteFrame(connection, body)
}
