// Package lobby implements the BOZ lobby and matchmaking protocol.
package lobby

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/auth"
	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

const (
	LSGServiceID byte = 0x07

	lsgLoginBodySize            = 140
	lsgAuthBlobSize             = 128
	lsgConnectionIDMessage byte = 0x04

	DefaultMaxRecords   = 0
	DefaultReadTimeout  = 2 * time.Minute
	DefaultWriteTimeout = 5 * time.Second
	DefaultProofTimeout = 10 * time.Second

	DefaultMaxProvisionalControlRecords = 8
)

var (
	ErrMalformedLSGLogin       = errors.New("lobby: malformed LSG login")
	ErrInvalidLSGIdentity      = errors.New("lobby: invalid LSG identity")
	ErrUnsupportedLobbyMessage = errors.New("lobby: unsupported post-login message")
	ErrRecordLimit             = errors.New("lobby: transport record limit reached")
	ErrProvisionalControlLimit = errors.New("lobby: provisional control record limit reached")
)

type LSGLogin struct {
	TitleID    uint32
	TicketSeed uint32
	AuthBlob   [lsgAuthBlobSize]byte
}

func ParseLSGLoginBody(body []byte) (LSGLogin, error) {
	if len(body) != lsgLoginBodySize {
		return LSGLogin{}, fmt.Errorf("%w: body is %d bytes, want %d", ErrMalformedLSGLogin, len(body), lsgLoginBodySize)
	}
	if body[0] != 0 || body[1] != LSGServiceID {
		return LSGLogin{}, fmt.Errorf("%w: envelope is %02x %02x", ErrMalformedLSGLogin, body[0], body[1])
	}
	reader := bitdemon.NewBitReader(body[2:])
	typeChecked, err := reader.ReadTypeCheckedFlag()
	if err != nil || !typeChecked {
		return LSGLogin{}, fmt.Errorf("%w: invalid type-check flag", ErrMalformedLSGLogin)
	}
	titleID, err := reader.ReadUint32()
	if err != nil {
		return LSGLogin{}, fmt.Errorf("%w: read title ID: %v", ErrMalformedLSGLogin, err)
	}
	if titleID != auth.BOZTitleID {
		return LSGLogin{}, ErrInvalidLSGIdentity
	}
	ticketSeed, err := reader.ReadUint32()
	if err != nil {
		return LSGLogin{}, fmt.Errorf("%w: read ticket seed: %v", ErrMalformedLSGLogin, err)
	}
	reader.SetTypeChecked(false)
	authBlobBytes, err := reader.ReadRaw(lsgAuthBlobSize)
	if err != nil {
		return LSGLogin{}, fmt.Errorf("%w: read authentication blob: %v", ErrMalformedLSGLogin, err)
	}
	if reader.RemainingBits() != 5 || body[len(body)-1]&0xf8 != 0 {
		return LSGLogin{}, fmt.Errorf("%w: nonzero or unexpected padding", ErrMalformedLSGLogin)
	}
	login := LSGLogin{TitleID: titleID, TicketSeed: ticketSeed}
	copy(login.AuthBlob[:], authBlobBytes)
	return login, nil
}

type HandlerConfig struct {
	MaxRecords                   int
	MaxProvisionalControlRecords int
	ReadTimeout                  time.Duration
	WriteTimeout                 time.Duration
	ProofTimeout                 time.Duration
	Random                       io.Reader
	Now                          func() time.Time
	Logger                       Logger
}

type Logger interface {
	Printf(format string, arguments ...any)
}

type Handler struct {
	config   HandlerConfig
	accounts *auth.MemoryAccountStore
	sessions *auth.MemoryLobbySessionStore
	matches  *MemoryMatchmakingStore
	clients  *activeLobbyClients
	nextID   atomic.Uint64
}

func NewHandler(config HandlerConfig, accounts *auth.MemoryAccountStore, sessions *auth.MemoryLobbySessionStore, matches *MemoryMatchmakingStore) (*Handler, error) {
	if accounts == nil || sessions == nil || matches == nil {
		return nil, errors.New("lobby: account, session, and matchmaking stores are required")
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = DefaultWriteTimeout
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = DefaultReadTimeout
	}
	if config.ProofTimeout == 0 {
		config.ProofTimeout = DefaultProofTimeout
	}
	if config.MaxProvisionalControlRecords == 0 {
		config.MaxProvisionalControlRecords = DefaultMaxProvisionalControlRecords
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxRecords < 0 || config.MaxRecords > 1_000_000 {
		return nil, errors.New("lobby: maximum records must be zero (unlimited) or between 1 and 1000000")
	}
	if config.MaxProvisionalControlRecords < 1 || config.MaxProvisionalControlRecords > 1024 {
		return nil, errors.New("lobby: maximum provisional control records must be between 1 and 1024")
	}
	if config.WriteTimeout < time.Second || config.WriteTimeout > time.Minute {
		return nil, errors.New("lobby: write timeout must be between 1s and 1m")
	}
	if config.ReadTimeout < 5*time.Second || config.ReadTimeout > 10*time.Minute {
		return nil, errors.New("lobby: read timeout must be between 5s and 10m")
	}
	if config.ProofTimeout < 10*time.Millisecond || config.ProofTimeout > time.Minute {
		return nil, errors.New("lobby: proof timeout must be between 10ms and 1m")
	}
	return &Handler{
		config:   config,
		accounts: accounts,
		sessions: sessions,
		matches:  matches,
		clients:  newActiveLobbyClients(),
	}, nil
}

func (handler *Handler) HandleTCP(ctx context.Context, connection net.Conn) error {
	client := &lobbyClient{connection: connection, writeTimeout: handler.config.WriteTimeout}
	authenticated := false
	sessionConfirmed := false
	var lobbySession auth.LobbySession
	var sessionToken auth.LobbySessionToken
	var connectionID uint64
	var transactionID uint64
	var proofDeadline time.Time
	provisionalControlRecords := 0
	defer func() {
		handler.clients.deactivate(client)
		if connectionID != 0 {
			handler.matches.DeleteOwner(connectionID)
			handler.logf("lobby disconnected user=%q connection=%d", client.account.Username,
				connectionID)
		}
	}()
	for recordIndex := 0; ; recordIndex++ {
		if handler.config.MaxRecords != 0 && recordIndex >= handler.config.MaxRecords {
			return ErrRecordLimit
		}
		if ctx.Err() != nil {
			return nil
		}
		readDeadline := time.Now().Add(handler.config.ReadTimeout)
		if authenticated && !sessionConfirmed && proofDeadline.Before(readDeadline) {
			readDeadline = proofDeadline
		}
		if err := connection.SetReadDeadline(readDeadline); err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
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
			if authenticated && !sessionConfirmed {
				provisionalControlRecords++
				if provisionalControlRecords > handler.config.MaxProvisionalControlRecords {
					return ErrProvisionalControlLimit
				}
			}
			if err := client.writeFrame(nil); err != nil {
				return err
			}
		case bitdemon.RecordKindBufferAvailable:
			if authenticated && !sessionConfirmed {
				provisionalControlRecords++
				if provisionalControlRecords > handler.config.MaxProvisionalControlRecords {
					return ErrProvisionalControlLimit
				}
			}
			continue
		case bitdemon.RecordKindFrame:
			if authenticated {
				request, err := decryptRequestBody(record.Body, lobbySession.SessionKey)
				if err != nil {
					return err
				}
				if !sessionConfirmed {
					confirmed, ok := handler.sessions.Consume(lobbySession.TicketSeed, sessionToken, connection.RemoteAddr(), handler.config.Now().UTC())
					if !ok {
						return ErrInvalidLSGIdentity
					}
					lobbySession = confirmed
					sessionConfirmed = true
					handler.clients.activate(client)
				}
				switch request.Service {
				case EventLogServiceID:
					event, err := parseEventLogRequest(request.Payload, request.Seed)
					if err != nil {
						return err
					}
					logicalReply := marshalTaskReply(transactionID, event.Task, statusNoError, 0, 0)
					replyBody := marshalClearTaskReplyBody(logicalReply)
					if err := client.writeFrame(replyBody); err != nil {
						return err
					}
					transactionID++
					continue
				case MatchmakingServiceID:
					matchmaking, err := parseMatchmakingRequest(request.Payload, request.Seed)
					if err != nil {
						return err
					}
					matchmaking, err = bindMatchmakingIdentity(matchmaking, client.account.Username)
					if err != nil {
						return err
					}
					replyBody, err := handler.handleMatchmaking(connectionID, transactionID, matchmaking)
					if err != nil {
						return err
					}
					if err := client.writeFrame(replyBody); err != nil {
						return err
					}
					transactionID++
					continue
				case MessagingServiceID:
					message, err := parseMessagingRequest(request.Payload, request.Seed)
					if err != nil {
						return err
					}
					delivered := handler.deliverGlobalInstantMessage(client, message)
					handler.logf("peer signal sender=%q recipient=%d delivered=%t bytes=%d",
						client.account.Username, message.Recipient, delivered, len(message.Message))
					replyBody := marshalClearTaskReplyBody(marshalTaskReply(transactionID, message.Task, statusNoError, 0, 0))
					if err := client.writeFrame(replyBody); err != nil {
						return err
					}
					transactionID++
					continue
				default:
					return fmt.Errorf("%w: service 0x%02x", ErrUnsupportedLobbyMessage, request.Service)
				}
			}
			login, err := ParseLSGLoginBody(record.Body)
			if err != nil {
				return err
			}
			if !allZero(login.AuthBlob[:]) {
				return ErrInvalidLSGIdentity
			}
			session, token, ok := handler.sessions.Lookup(login.TicketSeed, connection.RemoteAddr(), handler.config.Now().UTC())
			if !ok || session.TitleID != login.TitleID {
				return ErrInvalidLSGIdentity
			}
			account, ok := handler.accounts.LookupUserID(session.UserID)
			if !ok || account.AccountHash != session.AccountHash {
				return ErrInvalidLSGIdentity
			}
			client.account = account
			client.sessionKey = session.SessionKey
			connectionID = handler.nextID.Add(1)
			if connectionID == 0 {
				connectionID = handler.nextID.Add(1)
			}
			if err := handler.writeConnectionID(client, connectionID); err != nil {
				return err
			}
			handler.logf("lobby login user=%q connection=%d source=%q", account.Username,
				connectionID, connection.RemoteAddr().String())
			lobbySession = session
			sessionToken = token
			authenticated = true
			proofDeadline = time.Now().Add(handler.config.ProofTimeout)
		default:
			return errors.New("lobby: unknown transport record kind")
		}
	}
}

func (handler *Handler) deliverGlobalInstantMessage(sender *lobbyClient, request MessagingRequest) bool {
	recipient := handler.clients.lookup(request.Recipient)
	if recipient == nil {
		return false
	}
	senderName := sender.account.Username
	if len(senderName) > maxMessagingSenderNameBytes {
		senderName = senderName[:maxMessagingSenderNameBytes]
	}
	body, err := marshalGlobalInstantMessagePush(
		recipient.sessionKey,
		recipient.serverSeed(),
		sender.account.AccountHash,
		senderName,
		request.Message,
	)
	if err != nil {
		return false
	}
	if err := recipient.writeFrame(body); err != nil {
		handler.clients.deactivate(recipient)
		_ = recipient.connection.Close()
		return false
	}
	return true
}

func (handler *Handler) handleMatchmaking(connectionID, transactionID uint64, request MatchmakingRequest) ([]byte, error) {
	var logicalReply []byte
	switch request.Task {
	case MatchmakingTaskCreate:
		created, err := handler.matches.Create(connectionID, request.Info, handler.config.Random)
		if err != nil {
			return nil, err
		}
		logicalReply = marshalTaskReply(transactionID, request.Task, statusNoError, 1, 1)
		writer := bitdemon.NewByteWriter(true)
		writer.WriteRaw(logicalReply)
		if err := writeMatchmakingSessionID(writer, created.SessionID); err != nil {
			_ = handler.matches.Delete(connectionID, created.SessionID)
			return nil, err
		}
		logicalReply = writer.Bytes()
		handler.logf("match created owner=%d session=%x max_players=%d", connectionID,
			created.SessionID, created.MaxPlayers)
	case MatchmakingTaskUpdate:
		err := handler.matches.Update(connectionID, request.SessionID, request.Info)
		if err != nil && !errors.Is(err, ErrMatchmakingSessionMiss) {
			return nil, fmt.Errorf("update match %x: %w", request.SessionID, err)
		}
		logicalReply = marshalTaskReply(transactionID, request.Task, statusNoError, 0, 0)
		if err == nil {
			handler.logf("match updated owner=%d session=%x", connectionID, request.SessionID)
		} else {
			handler.logf("stale match update acknowledged owner=%d session=%x", connectionID, request.SessionID)
		}
	case MatchmakingTaskDelete:
		err := handler.matches.Delete(connectionID, request.SessionID)
		if err != nil && !errors.Is(err, ErrMatchmakingSessionMiss) {
			return nil, fmt.Errorf("delete match %x: %w", request.SessionID, err)
		}
		logicalReply = marshalTaskReply(transactionID, request.Task, statusNoError, 0, 0)
		if err == nil {
			handler.logf("match deleted owner=%d session=%x", connectionID, request.SessionID)
		} else {
			handler.logf("stale match delete acknowledged owner=%d session=%x", connectionID, request.SessionID)
		}
	case MatchmakingTaskFind:
		results, total := handler.matches.Find(request.Query, request.Offset, request.MaxResults)
		logicalReply = marshalTaskReply(transactionID, request.Task, statusNoError, uint32(len(results)), total)
		writer := bitdemon.NewByteWriter(true)
		writer.WriteRaw(logicalReply)
		for _, result := range results {
			if err := writeMatchmakingResult(writer, result); err != nil {
				return nil, err
			}
		}
		logicalReply = writer.Bytes()
		handler.logf("match searched owner=%d returned=%d total=%d offset=%d limit=%d",
			connectionID, len(results), total, request.Offset, request.MaxResults)
	default:
		return nil, ErrUnsupportedMatchmakingTask
	}
	return marshalClearTaskReplyBody(logicalReply), nil
}

func (handler *Handler) logf(format string, arguments ...any) {
	if handler.config.Logger != nil {
		handler.config.Logger.Printf(format, arguments...)
	}
}

func (handler *Handler) writeConnectionID(client *lobbyClient, connectionID uint64) error {
	body := make([]byte, 11)
	body[0] = 0
	body[1] = lsgConnectionIDMessage
	body[2] = byte(bitdemon.TypeUint64)
	binary.LittleEndian.PutUint64(body[3:11], connectionID)
	return client.writeFrame(body)
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
