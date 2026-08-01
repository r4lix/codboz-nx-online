package stun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	HeaderSize          = 20
	BindingRequestSize  = 28
	BindingResponseSize = 56

	transactionIDSize   = 16
	addressValueSize    = 8
	attributeHeaderSize = 4

	bindingRequestType  uint16 = 0x0001
	bindingResponseType uint16 = 0x0101

	mappedAddressAttribute   uint16 = 0x0001
	changeRequestAttribute   uint16 = 0x0003
	sourceAddressAttribute   uint16 = 0x0004
	changedAddressAttribute  uint16 = 0x0005
	matchmakingModeAttribute uint16 = 0xc0d0

	changeIPFlag   uint32 = 0x00000004
	changePortFlag uint32 = 0x00000002
	changeFlagMask        = changeIPFlag | changePortFlag

	ipv4Family               byte = 0x01
	matchmakingModeValueSize      = 4
)

var (
	ErrMalformedRequest         = errors.New("stun: malformed binding request")
	ErrUnsupportedMessageType   = errors.New("stun: unsupported message type")
	ErrUnsupportedAttribute     = errors.New("stun: unsupported request attribute")
	ErrUnsupportedChangeRequest = errors.New("stun: unsupported CHANGE-REQUEST flags")
	ErrInvalidEndpoint          = errors.New("stun: invalid response endpoint")
	ErrIPv4Only                 = errors.New("stun: only IPv4 endpoints are supported")
)

// TransactionID is the 128-bit transaction ID used by RFC 3489.
type TransactionID [transactionIDSize]byte

// BindingRequest contains the RFC 3489 fields used by BOZ.
type BindingRequest struct {
	TransactionID TransactionID
	ChangeIP      bool
	ChangePort    bool
}

// BindingResponseEndpoints contains the three addresses in a Binding response.
type BindingResponseEndpoints struct {
	MappedAddress  netip.AddrPort
	SourceAddress  netip.AddrPort
	ChangedAddress netip.AddrPort
}

// ParseBindingRequest parses the 28-byte Binding request sent by BOZ.
func ParseBindingRequest(packet []byte) (BindingRequest, error) {
	if len(packet) < HeaderSize {
		return BindingRequest{}, fmt.Errorf("%w: got %d bytes, need at least %d", ErrMalformedRequest, len(packet), HeaderSize)
	}

	messageType := binary.BigEndian.Uint16(packet[0:2])
	if messageType != bindingRequestType {
		return BindingRequest{}, fmt.Errorf("%w: 0x%04x", ErrUnsupportedMessageType, messageType)
	}

	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength != BindingRequestSize-HeaderSize {
		return BindingRequest{}, fmt.Errorf("%w: body length is %d, want %d", ErrMalformedRequest, messageLength, BindingRequestSize-HeaderSize)
	}
	if len(packet) != HeaderSize+messageLength {
		return BindingRequest{}, fmt.Errorf("%w: datagram length is %d, header declares %d", ErrMalformedRequest, len(packet), HeaderSize+messageLength)
	}

	attribute := packet[HeaderSize:]
	attributeType := binary.BigEndian.Uint16(attribute[0:2])
	if attributeType != changeRequestAttribute {
		return BindingRequest{}, fmt.Errorf("%w: 0x%04x", ErrUnsupportedAttribute, attributeType)
	}
	attributeLength := int(binary.BigEndian.Uint16(attribute[2:4]))
	if attributeLength != 4 {
		return BindingRequest{}, fmt.Errorf("%w: CHANGE-REQUEST length is %d, want 4", ErrMalformedRequest, attributeLength)
	}

	flags := binary.BigEndian.Uint32(attribute[attributeHeaderSize : attributeHeaderSize+attributeLength])
	if flags & ^uint32(changeFlagMask) != 0 {
		return BindingRequest{}, fmt.Errorf("%w: 0x%08x", ErrUnsupportedChangeRequest, flags)
	}

	request := BindingRequest{
		ChangeIP:   flags&changeIPFlag != 0,
		ChangePort: flags&changePortFlag != 0,
	}
	copy(request.TransactionID[:], packet[4:HeaderSize])
	return request, nil
}

// BuildBindingResponse builds the 56-byte Binding response expected by BOZ.
func BuildBindingResponse(request BindingRequest, endpoints BindingResponseEndpoints) ([]byte, error) {
	if err := validateEndpoint("mapped", endpoints.MappedAddress); err != nil {
		return nil, err
	}
	if err := validateEndpoint("source", endpoints.SourceAddress); err != nil {
		return nil, err
	}
	if err := validateEndpoint("changed", endpoints.ChangedAddress); err != nil {
		return nil, err
	}

	response := make([]byte, BindingResponseSize)
	binary.BigEndian.PutUint16(response[0:2], bindingResponseType)
	binary.BigEndian.PutUint16(response[2:4], BindingResponseSize-HeaderSize)
	copy(response[4:HeaderSize], request.TransactionID[:])

	offset := HeaderSize
	offset = putAddressAttribute(response, offset, mappedAddressAttribute, endpoints.MappedAddress)
	offset = putAddressAttribute(response, offset, sourceAddressAttribute, endpoints.SourceAddress)
	putAddressAttribute(response, offset, changedAddressAttribute, endpoints.ChangedAddress)
	return response, nil
}

func appendMatchmakingMode(response []byte, mode byte) []byte {
	if mode > 1 || len(response) < HeaderSize {
		return response
	}
	attributeSize := attributeHeaderSize + matchmakingModeValueSize
	result := make([]byte, len(response)+attributeSize)
	copy(result, response)
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)-HeaderSize))
	offset := len(response)
	binary.BigEndian.PutUint16(result[offset:offset+2], matchmakingModeAttribute)
	binary.BigEndian.PutUint16(result[offset+2:offset+4], matchmakingModeValueSize)
	copy(result[offset+4:offset+7], "BOZ")
	result[offset+7] = mode
	return result
}

func validateEndpoint(role string, endpoint netip.AddrPort) error {
	if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() {
		return fmt.Errorf("%w: %s address %q", ErrInvalidEndpoint, role, endpoint)
	}
	if !endpoint.Addr().Is4() {
		return fmt.Errorf("%w: %s address %q", ErrIPv4Only, role, endpoint)
	}
	if !endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback() && !endpoint.Addr().IsLinkLocalUnicast() {
		return fmt.Errorf("%w: %s address %q is not specific unicast", ErrInvalidEndpoint, role, endpoint)
	}
	return nil
}

func putAddressAttribute(packet []byte, offset int, attributeType uint16, endpoint netip.AddrPort) int {
	binary.BigEndian.PutUint16(packet[offset:offset+2], attributeType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], addressValueSize)
	packet[offset+4] = 0
	packet[offset+5] = ipv4Family
	binary.BigEndian.PutUint16(packet[offset+6:offset+8], endpoint.Port())
	address := endpoint.Addr().As4()
	copy(packet[offset+8:offset+12], address[:])
	return offset + attributeHeaderSize + addressValueSize
}
