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
	"syscall"
	"time"

	onlineauth "github.com/Producdevity/cod-boz-netplay/internal/online/auth"
	"github.com/Producdevity/cod-boz-netplay/internal/online/backend"
	"github.com/Producdevity/cod-boz-netplay/internal/online/lobby"
	onlineserver "github.com/Producdevity/cod-boz-netplay/internal/online/server"
	"github.com/Producdevity/cod-boz-netplay/internal/online/stun"
)

type options struct {
	tcpAddress string
	udpAddress string
	stunSource netip.AddrPort
	dataDir    string
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
	service, err := onlineserver.New(onlineserver.Config{}, handler)
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
	opts := options{}
	var stunSourceText string
	flags := flag.NewFlagSet("codboz-online-server", flag.ContinueOnError)
	flags.SetOutput(logger.Writer())
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: codboz-online-server --stun-source-address IPv4:PORT [flags]")
		flags.PrintDefaults()
	}
	flags.StringVar(&opts.tcpAddress, "tcp-listen", ":3074", "authentication and lobby TCP listen address")
	flags.StringVar(&opts.udpAddress, "udp-listen", ":3478", "STUN and rendezvous UDP listen address")
	flags.StringVar(&opts.dataDir, "data-dir", "data", "directory for persistent server state")
	flags.StringVar(&stunSourceText, "stun-source-address", "", "reachable IPv4 address:port advertised by STUN")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments; use flags only")
	}
	if opts.tcpAddress == "" || opts.udpAddress == "" {
		return options{}, errors.New("TCP and UDP listen addresses must not be empty")
	}
	if opts.dataDir == "" {
		return options{}, errors.New("data directory must not be empty")
	}
	if stunSourceText == "" {
		return options{}, errors.New("--stun-source-address is required")
	}
	if err := assignSTUNSource(&opts, stunSourceText); err != nil {
		return options{}, err
	}
	return opts, nil
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
