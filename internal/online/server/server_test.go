package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingHandler struct {
	tcp chan []byte
	udp chan []byte
}

func (handler *recordingHandler) HandleTCP(_ context.Context, connection net.Conn) error {
	buffer := make([]byte, 64)
	count, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	handler.tcp <- append([]byte(nil), buffer[:count]...)
	return nil
}

func (handler *recordingHandler) HandleUDP(_ context.Context, _ net.PacketConn, _ net.Addr, payload []byte) error {
	handler.udp <- append([]byte(nil), payload...)
	return nil
}

func TestServeHandlesTCPAndUDPAndShutsDown(t *testing.T) {
	listener := newMemoryListener()
	packetConnection := newMemoryPacketConn()
	handler := &recordingHandler{
		tcp: make(chan []byte, 1),
		udp: make(chan []byte, 1),
	}
	service, err := New(Config{}, handler)
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(listener, packetConnection) }()

	serverConnection, clientConnection := net.Pipe()
	listener.accepts <- &remoteConn{
		Conn:   serverConnection,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
	}
	if _, err := clientConnection.Write([]byte("auth-request")); err != nil {
		t.Fatal(err)
	}
	_ = clientConnection.Close()
	packetConnection.reads <- memoryDatagram{
		payload: []byte("stun-request"),
		peer:    &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50001},
	}

	assertPayload(t, handler.tcp, "auth-request")
	assertPayload(t, handler.udp, "stun-request")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestReserveTCPConnectionCapsEachSource(t *testing.T) {
	service, err := New(Config{
		MaxTCPConnections:          3,
		MaxTCPConnectionsPerSource: 2,
	}, noOpHandler{})
	if err != nil {
		t.Fatal(err)
	}

	first, firstPeer := addressedPipe(t, "192.0.2.10", 50000)
	second, secondPeer := addressedPipe(t, "192.0.2.10", 50001)
	blocked, blockedPeer := addressedPipe(t, "192.0.2.10", 50002)
	other, otherPeer := addressedPipe(t, "192.0.2.11", 50003)
	defer firstPeer.Close()
	defer secondPeer.Close()
	defer blockedPeer.Close()
	defer otherPeer.Close()

	firstSource, ok := service.reserveTCPConnection(first)
	if !ok {
		t.Fatal("first connection was rejected")
	}
	secondSource, ok := service.reserveTCPConnection(second)
	if !ok {
		t.Fatal("second connection was rejected")
	}
	if _, ok := service.reserveTCPConnection(blocked); ok {
		t.Fatal("third connection from one source was accepted")
	}
	otherSource, ok := service.reserveTCPConnection(other)
	if !ok {
		t.Fatal("connection from another source was rejected")
	}

	service.releaseTCPConnection(first, firstSource)
	service.workers.Done()
	service.releaseTCPConnection(second, secondSource)
	service.workers.Done()
	service.releaseTCPConnection(other, otherSource)
	service.workers.Done()
	_ = first.Close()
	_ = second.Close()
	_ = blocked.Close()
	_ = other.Close()
}

func TestTCPSourceIdentityGroupsIPv6Prefix(t *testing.T) {
	first, ok := tcpSourceIdentity(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	if !ok {
		t.Fatal("first IPv6 source was rejected")
	}
	second, ok := tcpSourceIdentity(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 2})
	if !ok || first != second {
		t.Fatalf("IPv6 sources = %q, %q", first, second)
	}
	if _, ok := tcpSourceIdentity(&net.TCPAddr{IP: net.IPv4zero, Port: 3}); ok {
		t.Fatal("unspecified source was accepted")
	}
}

func assertPayload(t *testing.T, received <-chan []byte, want string) {
	t.Helper()
	select {
	case payload := <-received:
		if string(payload) != want {
			t.Fatalf("payload = %q, want %q", payload, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

func addressedPipe(t *testing.T, address string, port int) (*remoteConn, net.Conn) {
	t.Helper()
	serverConnection, peerConnection := net.Pipe()
	return &remoteConn{
		Conn:   serverConnection,
		remote: &net.TCPAddr{IP: net.ParseIP(address), Port: port},
	}, peerConnection
}

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (connection *remoteConn) RemoteAddr() net.Addr {
	return connection.remote
}

type memoryListener struct {
	accepts chan net.Conn
	closed  chan struct{}
	once    sync.Once
}

func newMemoryListener() *memoryListener {
	return &memoryListener{
		accepts: make(chan net.Conn, 1),
		closed:  make(chan struct{}),
	}
}

func (listener *memoryListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.accepts:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *memoryListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (listener *memoryListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 3074}
}

type memoryDatagram struct {
	payload []byte
	peer    net.Addr
}

type memoryPacketConn struct {
	reads  chan memoryDatagram
	closed chan struct{}
	once   sync.Once
}

func newMemoryPacketConn() *memoryPacketConn {
	return &memoryPacketConn{
		reads:  make(chan memoryDatagram, 1),
		closed: make(chan struct{}),
	}
}

func (connection *memoryPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case datagram := <-connection.reads:
		return copy(buffer, datagram.payload), datagram.peer, nil
	case <-connection.closed:
		return 0, nil, net.ErrClosed
	}
}

func (connection *memoryPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}

func (connection *memoryPacketConn) Close() error {
	connection.once.Do(func() { close(connection.closed) })
	return nil
}

func (connection *memoryPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 3478}
}

func (connection *memoryPacketConn) SetDeadline(time.Time) error      { return nil }
func (connection *memoryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }
