// Package backend routes BOZ TCP connections to authentication or lobby code.
package backend

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Producdevity/cod-boz-online/internal/online/auth"
	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
	"github.com/Producdevity/cod-boz-online/internal/online/lobby"
)

const (
	maxLeadingControlRecords  = 32
	maxInitialFrameBody       = 256
	DefaultInitialReadTimeout = 10 * time.Second
)

var ErrUnsupportedInitialMessage = errors.New("backend: unsupported initial TCP message")

type TCPHandler interface {
	HandleTCP(context.Context, net.Conn) error
}

type TCPRouter struct {
	auth               TCPHandler
	lobby              TCPHandler
	initialReadTimeout time.Duration
}

func NewTCPRouter(authHandler, lobbyHandler TCPHandler) (*TCPRouter, error) {
	return newTCPRouter(authHandler, lobbyHandler, DefaultInitialReadTimeout)
}

func newTCPRouter(authHandler, lobbyHandler TCPHandler, initialReadTimeout time.Duration) (*TCPRouter, error) {
	if authHandler == nil || lobbyHandler == nil {
		return nil, errors.New("backend: authentication and lobby handlers are required")
	}
	if initialReadTimeout < 10*time.Millisecond || initialReadTimeout > time.Minute {
		return nil, errors.New("backend: initial read timeout must be between 10ms and 1m")
	}
	return &TCPRouter{auth: authHandler, lobby: lobbyHandler, initialReadTimeout: initialReadTimeout}, nil
}

func (router *TCPRouter) HandleTCP(ctx context.Context, connection net.Conn) error {
	if err := connection.SetReadDeadline(time.Now().Add(router.initialReadTimeout)); err != nil {
		return err
	}
	reader := bufio.NewReader(connection)
	offset := 0
	for controlCount := 0; controlCount <= maxLeadingControlRecords; controlCount++ {
		prefix, err := reader.Peek(offset + bitdemon.FramePrefixSize)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		bodySize := binary.LittleEndian.Uint32(prefix[offset : offset+bitdemon.FramePrefixSize])
		switch bodySize {
		case bitdemon.LobbyKeepaliveBodyLen:
			offset += bitdemon.FramePrefixSize
			continue
		case bitdemon.BufferAvailableRecordMarker:
			offset += 8
			continue
		}
		if bodySize < 2 || bodySize > maxInitialFrameBody {
			return fmt.Errorf("%w: initial frame body size %d", ErrUnsupportedInitialMessage, bodySize)
		}
		header, err := reader.Peek(offset + bitdemon.FramePrefixSize + 2)
		if err != nil {
			return err
		}
		bodyOffset := offset + bitdemon.FramePrefixSize
		if header[bodyOffset] != 0 {
			return fmt.Errorf("%w: encrypted initial frame", ErrUnsupportedInitialMessage)
		}
		messageType := header[bodyOffset+1]
		if _, err := reader.Peek(offset + bitdemon.FramePrefixSize + int(bodySize)); err != nil {
			return err
		}
		buffered := &bufferedConn{Conn: connection, reader: reader}
		switch messageType {
		case auth.MessageCreateAccountRequest, auth.MessageAccountForMMPRequest:
			return router.auth.HandleTCP(ctx, buffered)
		case lobby.LSGServiceID:
			return router.lobby.HandleTCP(ctx, buffered)
		default:
			return fmt.Errorf("%w: type 0x%02x", ErrUnsupportedInitialMessage, messageType)
		}
	}
	return fmt.Errorf("%w: too many leading control records", ErrUnsupportedInitialMessage)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}
