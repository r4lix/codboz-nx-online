package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

var (
	ErrAlreadyServing = errors.New("online server is already serving")
	ErrShuttingDown   = errors.New("online server is shutting down")
)

type Handler interface {
	HandleTCP(context.Context, net.Conn) error
	HandleUDP(context.Context, net.PacketConn, net.Addr, []byte) error
}

type Server struct {
	config  Config
	handler Handler

	mu                  sync.Mutex
	serving             bool
	shuttingDown        bool
	tcpListener         net.Listener
	udpConn             net.PacketConn
	connections         map[net.Conn]struct{}
	connectionsBySource map[string]int
	cancel              context.CancelFunc
	done                chan struct{}
	workers             sync.WaitGroup
	connectionSlots     chan struct{}
}

func New(config Config, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("online protocol handler is required")
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:              normalized,
		handler:             handler,
		connections:         make(map[net.Conn]struct{}),
		connectionsBySource: make(map[string]int),
		connectionSlots:     make(chan struct{}, normalized.MaxTCPConnections),
	}, nil
}

func (s *Server) Serve(tcpListener net.Listener, udpConn net.PacketConn) error {
	if tcpListener == nil || udpConn == nil {
		return errors.New("TCP listener and UDP packet connection are required")
	}

	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return ErrAlreadyServing
	}
	if s.shuttingDown {
		s.mu.Unlock()
		return ErrShuttingDown
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.serving = true
	s.tcpListener = tcpListener
	s.udpConn = udpConn
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()

	results := make(chan error, 2)
	go func() { results <- s.serveTCP(ctx, tcpListener) }()
	go func() { results <- s.serveUDP(ctx, udpConn) }()

	first := <-results
	cancel()
	_ = tcpListener.Close()
	_ = udpConn.Close()
	second := <-results
	s.closeConnections()
	s.workers.Wait()

	s.mu.Lock()
	shuttingDown := s.shuttingDown
	s.serving = false
	s.tcpListener = nil
	s.udpConn = nil
	s.cancel = nil
	close(done)
	s.mu.Unlock()

	if shuttingDown {
		return nil
	}
	if first != nil {
		return first
	}
	return second
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept TCP connection: %w", err)
		}

		source, accepted := s.reserveTCPConnection(connection)
		if !accepted {
			_ = connection.Close()
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		go s.handleTCP(ctx, connection, source)
	}
}

func (s *Server) reserveTCPConnection(connection net.Conn) (string, bool) {
	source, ok := tcpSourceIdentity(connection.RemoteAddr())
	if !ok {
		return "", false
	}
	select {
	case s.connectionSlots <- struct{}{}:
	default:
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown || s.connectionsBySource[source] >= s.config.MaxTCPConnectionsPerSource {
		<-s.connectionSlots
		return "", false
	}
	s.connections[connection] = struct{}{}
	s.connectionsBySource[source]++
	s.workers.Add(1)
	return source, true
}

func (s *Server) handleTCP(ctx context.Context, connection net.Conn, source string) {
	defer s.workers.Done()
	defer s.releaseTCPConnection(connection, source)
	defer connection.Close()
	_ = s.handler.HandleTCP(ctx, connection)
}

func (s *Server) releaseTCPConnection(connection net.Conn, source string) {
	s.mu.Lock()
	delete(s.connections, connection)
	remaining := s.connectionsBySource[source] - 1
	if remaining <= 0 {
		delete(s.connectionsBySource, source)
	} else {
		s.connectionsBySource[source] = remaining
	}
	s.mu.Unlock()
	<-s.connectionSlots
}

func (s *Server) serveUDP(ctx context.Context, connection net.PacketConn) error {
	buffer := make([]byte, MaxUDPDatagramBytes)
	for {
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP datagram: %w", err)
		}
		payload := append([]byte(nil), buffer[:count]...)
		if err := s.handler.HandleUDP(ctx, connection, peer, payload); err != nil && ctx.Err() == nil {
			return fmt.Errorf("handle UDP datagram from %s: %w", peer, err)
		}
	}
}

func tcpSourceIdentity(peer net.Addr) (string, bool) {
	if peer == nil {
		return "", false
	}
	var address netip.Addr
	if tcpPeer, ok := peer.(*net.TCPAddr); ok {
		var valid bool
		address, valid = netip.AddrFromSlice(tcpPeer.IP)
		if !valid {
			return "", false
		}
	} else {
		host, _, err := net.SplitHostPort(peer.String())
		if err != nil {
			return "", false
		}
		address, err = netip.ParseAddr(host)
		if err != nil {
			return "", false
		}
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return "", false
	}
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String(), true
	}
	return address.String(), true
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.serving {
		s.shuttingDown = true
		s.mu.Unlock()
		return nil
	}
	if !s.shuttingDown {
		s.shuttingDown = true
		if s.cancel != nil {
			s.cancel()
		}
		_ = s.tcpListener.Close()
		_ = s.udpConn.Close()
	}
	done := s.done
	s.mu.Unlock()

	s.closeConnections()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) closeConnections() {
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}
