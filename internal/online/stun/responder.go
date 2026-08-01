package stun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	publisherLease = 10 * time.Second
	peerModeTTL    = 5 * time.Minute
	maxPeerModes   = 4096
)

type ResponderConfig struct {
	SourceAddress  netip.AddrPort
	ChangedAddress netip.AddrPort
	HasSessions    func() bool
}

type Responder struct {
	config         ResponderConfig
	mu             sync.Mutex
	publisherUntil time.Time
	peerModes      map[netip.AddrPort]peerMode
}

type peerMode struct {
	value     byte
	expiresAt time.Time
}

func NewResponder(config ResponderConfig) (*Responder, error) {
	_, err := BuildBindingResponse(BindingRequest{}, BindingResponseEndpoints{
		MappedAddress:  netip.MustParseAddrPort("192.0.2.1:1"),
		SourceAddress:  config.SourceAddress,
		ChangedAddress: config.ChangedAddress,
	})
	if err != nil {
		return nil, fmt.Errorf("configure STUN responder: %w", err)
	}
	return &Responder{config: config, peerModes: make(map[netip.AddrPort]peerMode)}, nil
}

func (responder *Responder) HandleUDP(ctx context.Context, connection net.PacketConn, peer net.Addr, payload []byte) error {
	if ctx.Err() != nil || connection == nil {
		return nil
	}
	request, err := ParseBindingRequest(payload)
	if err != nil || request.ChangeIP || request.ChangePort {
		return nil
	}
	mappedAddress, ok := udpAddrPort(peer)
	if !ok {
		return nil
	}
	response, err := BuildBindingResponse(request, BindingResponseEndpoints{
		MappedAddress:  mappedAddress,
		SourceAddress:  responder.config.SourceAddress,
		ChangedAddress: responder.config.ChangedAddress,
	})
	if err != nil {
		return fmt.Errorf("build STUN response: %w", err)
	}
	response = appendMatchmakingMode(response, responder.matchmakingMode(mappedAddress, time.Now()))
	written, err := connection.WriteTo(response, peer)
	if err != nil {
		return fmt.Errorf("write STUN response: %w", err)
	}
	if written != len(response) {
		return io.ErrShortWrite
	}
	return nil
}

func (responder *Responder) matchmakingMode(peer netip.AddrPort, now time.Time) byte {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if cached, ok := responder.peerModes[peer]; ok && now.Before(cached.expiresAt) {
		return cached.value
	}
	for endpoint, cached := range responder.peerModes {
		if !now.Before(cached.expiresAt) {
			delete(responder.peerModes, endpoint)
		}
	}
	if len(responder.peerModes) >= maxPeerModes {
		return 1
	}
	mode := byte(1)
	hasSessions := responder.config.HasSessions != nil && responder.config.HasSessions()
	if !hasSessions && !now.Before(responder.publisherUntil) {
		mode = 0
		responder.publisherUntil = now.Add(publisherLease)
	}
	responder.peerModes[peer] = peerMode{value: mode, expiresAt: now.Add(peerModeTTL)}
	return mode
}

func udpAddrPort(peer net.Addr) (netip.AddrPort, bool) {
	udpAddress, ok := peer.(*net.UDPAddr)
	if !ok || udpAddress.Port < 1 || udpAddress.Port > 65535 {
		return netip.AddrPort{}, false
	}
	address, ok := netip.AddrFromSlice(udpAddress.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	address = address.Unmap()
	if !address.Is4() || address.IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(address, uint16(udpAddress.Port)), true
}
