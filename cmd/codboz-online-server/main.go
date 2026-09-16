package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	onlineauth "github.com/Producdevity/cod-boz-online/internal/online/auth"
	"github.com/Producdevity/cod-boz-online/internal/online/backend"
	"github.com/Producdevity/cod-boz-online/internal/online/lobby"
	onlineserver "github.com/Producdevity/cod-boz-online/internal/online/server"
	"github.com/Producdevity/cod-boz-online/internal/online/stun"
)

// stunSourceAuto asks the server to advertise the IPv4 address of the
// interface it reaches the network through. That is the right answer for a
// LAN server and for a host with a public address on its own interface; a
// server behind port forwarding must still be given its public address.
const stunSourceAuto = "auto"

// Environment variables mirror the flags, so container platforms that only
// offer variables (Unraid templates, compose files) can configure everything.
// A flag given on the command line wins over its variable.
const (
	envTCPListen                  = "CODBOZ_TCP_LISTEN"
	envUDPListen                  = "CODBOZ_UDP_LISTEN"
	envDataDir                    = "CODBOZ_DATA_DIR"
	envSTUNSource                 = "CODBOZ_STUN_ADDRESS"
	envMaxTCPConnections          = "CODBOZ_MAX_TCP_CONNECTIONS"
	envMaxTCPConnectionsPerSource = "CODBOZ_MAX_TCP_CONNECTIONS_PER_SOURCE"
)

type options struct {
	tcpAddress                 string
	udpAddress                 string
	stunSource                 netip.AddrPort
	stunSourceDetected         bool
	dataDir                    string
	maxTCPConnections          int
	maxTCPConnectionsPerSource int
	healthcheck                bool
}

// lookupEnv is os.LookupEnv, replaceable in tests.
type lookupEnv func(key string) (string, bool)

// detectOutboundIPv4 reports the local IPv4 address used to reach the
// network. Dialing UDP sends nothing; it only makes the kernel choose a route
// and a source address. Replaceable in tests.
var detectOutboundIPv4 = func() (netip.Addr, error) {
	connection, err := net.Dial("udp4", "192.0.2.1:3478")
	if err != nil {
		return netip.Addr{}, err
	}
	defer connection.Close()
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address type")
	}
	address, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, errors.New("unparseable local address")
	}
	return address.Unmap(), nil
}

func main() {
	logger := log.New(os.Stderr, "codboz-online-server: ", log.Ldate|log.Ltime|log.LUTC)
	if err := run(os.Args[1:], logger); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run(args []string, logger *log.Logger) error {
	opts, err := parseOptions(args, logger)
	if err != nil {
		return err
	}
	if opts.healthcheck {
		return checkHealth(opts.tcpAddress, 3*time.Second)
	}
	if opts.stunSourceDetected {
		logger.Printf("STUN source address detected as %s (set %s or --stun-source-address to override)", opts.stunSource, envSTUNSource)
	}

	accounts, err := onlineauth.NewMemoryAccountStoreWithConfig(onlineauth.MemoryAccountStoreConfig{
		StateFile: filepath.Join(opts.dataDir, "accounts.json"),
	})
	if err != nil {
		return fmt.Errorf("configure account store: %w", err)
	}
	sessions, err := onlineauth.NewMemoryLobbySessionStoreWithConfig(onlineauth.MemoryLobbySessionStoreConfig{})
	if err != nil {
		return fmt.Errorf("configure lobby session store: %w", err)
	}
	matches, err := lobby.NewMemoryMatchmakingStoreWithConfig(lobby.MemoryMatchmakingStoreConfig{})
	if err != nil {
		return fmt.Errorf("configure matchmaking store: %w", err)
	}
	authHandler, err := onlineauth.NewHandler(onlineauth.HandlerConfig{}, accounts, sessions)
	if err != nil {
		return fmt.Errorf("configure auth handler: %w", err)
	}
	lobbyHandler, err := lobby.NewHandler(lobby.HandlerConfig{Logger: logger}, accounts, sessions, matches)
	if err != nil {
		return fmt.Errorf("configure lobby handler: %w", err)
	}
	tcpHandler, err := backend.NewTCPRouter(authHandler, lobbyHandler)
	if err != nil {
		return fmt.Errorf("configure TCP router: %w", err)
	}
	stunHandler, err := stun.NewResponder(stun.ResponderConfig{
		SourceAddress:  opts.stunSource,
		ChangedAddress: opts.stunSource,
	})
	if err != nil {
		return fmt.Errorf("configure STUN responder: %w", err)
	}
	handler := &runtimeHandler{tcp: tcpHandler, stun: stunHandler, logger: logger}
	service, err := onlineserver.New(onlineserver.Config{
		MaxTCPConnections:          opts.maxTCPConnections,
		MaxTCPConnectionsPerSource: opts.maxTCPConnectionsPerSource,
	}, handler)
	if err != nil {
		return fmt.Errorf("configure online server: %w", err)
	}

	tcpListener, err := net.Listen("tcp", opts.tcpAddress)
	if err != nil {
		return fmt.Errorf("listen for native TCP on %q: %w", opts.tcpAddress, err)
	}
	defer tcpListener.Close()
	udpConnection, err := net.ListenPacket("udp", opts.udpAddress)
	if err != nil {
		return fmt.Errorf("listen for native UDP on %q: %w", opts.udpAddress, err)
	}
	defer udpConnection.Close()

	logger.Printf("native backend listening; TCP=%s UDP=%s STUN-source=%s data=%s", tcpListener.Addr(), udpConnection.LocalAddr(), opts.stunSource, opts.dataDir)
	return serveUntilSignal(service, tcpListener, udpConnection, onlineserver.DefaultConfig().ShutdownTimeout, logger)
}

type runtimeHandler struct {
	tcp    backend.TCPHandler
	stun   *stun.Responder
	logger *log.Logger
}

func (handler *runtimeHandler) HandleTCP(ctx context.Context, connection net.Conn) error {
	err := handler.tcp.HandleTCP(ctx, connection)
	if err != nil && ctx.Err() == nil && handler.logger != nil {
		handler.logger.Printf("TCP client %s closed with protocol error: %v", connection.RemoteAddr(), err)
	}
	return err
}

func (handler *runtimeHandler) HandleUDP(ctx context.Context, connection net.PacketConn, peer net.Addr, payload []byte) error {
	err := handler.stun.HandleUDP(ctx, connection, peer, payload)
	if err != nil && ctx.Err() == nil && handler.logger != nil {
		handler.logger.Printf("UDP client %s response error: %v", peer, err)
	}
	return nil
}

func parseOptions(args []string, logger *log.Logger) (options, error) {
	return parseOptionsWithEnv(args, logger, os.LookupEnv)
}

func parseOptionsWithEnv(args []string, logger *log.Logger, env lookupEnv) (options, error) {
	opts := options{}
	var stunSourceText string
	defaults := onlineserver.DefaultConfig()

	stringDefault := func(key, fallback string) string {
		if value, ok := env(key); ok {
			return value
		}
		return fallback
	}
	intDefault := func(key string, fallback int) (int, error) {
		value, ok := env(key)
		if !ok || value == "" {
			return fallback, nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", key, err)
		}
		return parsed, nil
	}
	maxConnectionsDefault, err := intDefault(envMaxTCPConnections, defaults.MaxTCPConnections)
	if err != nil {
		return options{}, err
	}
	maxPerSourceDefault, err := intDefault(envMaxTCPConnectionsPerSource, defaults.MaxTCPConnectionsPerSource)
	if err != nil {
		return options{}, err
	}

	flags := flag.NewFlagSet("codboz-online-server", flag.ContinueOnError)
	flags.SetOutput(logger.Writer())
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: codboz-online-server --stun-source-address IPv4:PORT|auto [flags]")
		fmt.Fprintln(flags.Output(), "Every flag can also be set with its CODBOZ_* environment variable; the flag wins.")
		flags.PrintDefaults()
	}
	flags.StringVar(&opts.tcpAddress, "tcp-listen", stringDefault(envTCPListen, ":3074"), "authentication and lobby TCP listen address ("+envTCPListen+")")
	flags.StringVar(&opts.udpAddress, "udp-listen", stringDefault(envUDPListen, ":3478"), "STUN and rendezvous UDP listen address ("+envUDPListen+")")
	flags.StringVar(&opts.dataDir, "data-dir", stringDefault(envDataDir, "data"), "directory for persistent server state ("+envDataDir+")")
	flags.StringVar(&stunSourceText, "stun-source-address", stringDefault(envSTUNSource, ""), "reachable IPv4 address:port advertised by STUN, or \"auto\" for this host's outbound IPv4 and the UDP listen port ("+envSTUNSource+")")
	flags.IntVar(&opts.maxTCPConnections, "max-tcp-connections", maxConnectionsDefault, "maximum concurrent TCP connections ("+envMaxTCPConnections+")")
	flags.IntVar(&opts.maxTCPConnectionsPerSource, "max-tcp-connections-per-source", maxPerSourceDefault, "maximum concurrent TCP connections from one source address; raise it when several players share a public IP ("+envMaxTCPConnectionsPerSource+")")
	flags.BoolVar(&opts.healthcheck, "healthcheck", false, "check that a server is accepting TCP connections on the listen port, then exit 0 (healthy) or 1")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments; use flags only")
	}
	if opts.tcpAddress == "" || opts.udpAddress == "" {
		return options{}, errors.New("TCP and UDP listen addresses must not be empty")
	}
	if opts.healthcheck {
		return opts, nil
	}
	if opts.dataDir == "" {
		return options{}, errors.New("data directory must not be empty")
	}
	if err := validateLimits(opts.maxTCPConnections, opts.maxTCPConnectionsPerSource); err != nil {
		return options{}, err
	}
	if stunSourceText == "" {
		return options{}, fmt.Errorf("--stun-source-address (or %s) is required; use \"auto\" for a LAN server", envSTUNSource)
	}
	if stunSourceText == stunSourceAuto {
		detected, err := detectSTUNSource(opts.udpAddress)
		if err != nil {
			return options{}, err
		}
		stunSourceText = detected.String()
		opts.stunSourceDetected = true
	}
	if err := assignSTUNSource(&opts, stunSourceText); err != nil {
		return options{}, err
	}
	return opts, nil
}

func validateLimits(maxConnections, maxPerSource int) error {
	if maxConnections < 1 || maxConnections > onlineserver.MaxTCPConnectionsLimit {
		return fmt.Errorf("--max-tcp-connections must be between 1 and %d", onlineserver.MaxTCPConnectionsLimit)
	}
	if maxPerSource < 1 || maxPerSource > onlineserver.MaxTCPConnectionsPerSourceLimit {
		return fmt.Errorf("--max-tcp-connections-per-source must be between 1 and %d", onlineserver.MaxTCPConnectionsPerSourceLimit)
	}
	if maxPerSource > maxConnections {
		return errors.New("--max-tcp-connections-per-source must not exceed --max-tcp-connections")
	}
	return nil
}

// detectSTUNSource combines the outbound IPv4 address with the UDP listen
// port, which is where clients' STUN requests actually arrive.
func detectSTUNSource(udpAddress string) (netip.AddrPort, error) {
	_, portText, err := net.SplitHostPort(udpAddress)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("auto STUN source: parse UDP listen address %q: %w", udpAddress, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("auto STUN source: UDP listen address %q needs a fixed port", udpAddress)
	}
	address, err := detectOutboundIPv4()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("auto STUN source: detect outbound IPv4: %w", err)
	}
	if !address.Is4() || address.IsLoopback() || address.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("auto STUN source: detected %s, which clients cannot reach; set the address explicitly", address)
	}
	return netip.AddrPortFrom(address, uint16(port)), nil
}

func assignSTUNSource(opts *options, sourceText string) error {
	parsedSource, err := netip.ParseAddrPort(sourceText)
	if err != nil {
		return fmt.Errorf("parse --stun-source-address: %w", err)
	}
	opts.stunSource = parsedSource
	if _, err := stun.NewResponder(stun.ResponderConfig{
		SourceAddress:  opts.stunSource,
		ChangedAddress: opts.stunSource,
	}); err != nil {
		return err
	}
	return nil
}

// checkHealth connects to the TCP listener on loopback. The image has no shell
// or curl, so the binary checks itself; the lobby protocol does not need to be
// spoken, since accepting the connection is what proves the server is up.
func checkHealth(tcpAddress string, timeout time.Duration) error {
	_, port, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		return fmt.Errorf("healthcheck: parse TCP listen address %q: %w", tcpAddress, err)
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), timeout)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	return connection.Close()
}

func serveUntilSignal(service *onlineserver.Server, tcpListener net.Listener, udpConnection net.PacketConn, shutdownTimeout time.Duration, logger *log.Logger) error {
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(tcpListener, udpConnection) }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serveResult:
		return err
	case received := <-signals:
		logger.Printf("received %s; starting graceful shutdown", received)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-serveResult; err != nil {
		return err
	}
	logger.Print("shutdown complete")
	return nil
}
