package lobby

import (
	"errors"
	"fmt"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

const (
	MatchmakingServiceID byte = 0x15

	MatchmakingTaskCreate byte = 0x01
	MatchmakingTaskUpdate byte = 0x02
	MatchmakingTaskDelete byte = 0x03
	MatchmakingTaskFind   byte = 0x05

	matchmakingSessionIDSize = 8
	maxHostAddressSize       = 255
	maxMatchmakingTextBytes  = 31
	maxFindResults           = 50
)

var (
	ErrMalformedMatchmakingRequest = errors.New("lobby: malformed matchmaking request")
	ErrMatchmakingIdentity         = errors.New("lobby: matchmaking identity is too long")
	ErrUnsupportedMatchmakingTask  = errors.New("lobby: unsupported matchmaking task")
	ErrUnsupportedMatchmakingQuery = errors.New("lobby: unsupported matchmaking query")
)

type MatchmakingSessionID [matchmakingSessionIDSize]byte

// MatchmakingAttributes mirrors fields whose gameplay meanings are not all
// known. The names use their offsets in the original class. Fields 0x11c and
// 0x158 contain the lowercase DJB2 hash used by the private query.
type MatchmakingAttributes struct {
	AppU32At11C    uint32
	AppU32At120    uint32
	AppU64At128    uint64
	AppStringAt130 string
	AppU32At154    uint32
	AppU32At158    uint32
	AppI32At15C    int32
}

type MatchmakingInfo struct {
	HostAddress []byte
	SessionID   MatchmakingSessionID
	GameType    uint32
	MaxPlayers  uint32
	NumPlayers  uint32
	Attributes  MatchmakingAttributes
}

type MatchmakingQuery struct {
	AttributeHash  uint32
	AttributeValue int32
}

type MatchmakingRequest struct {
	Task       byte
	SessionID  MatchmakingSessionID
	Info       MatchmakingInfo
	NumParams  uint32
	Offset     uint32
	MaxResults uint32
	Query      MatchmakingQuery
}

func bindMatchmakingIdentity(request MatchmakingRequest, username string) (MatchmakingRequest, error) {
	if request.Task != MatchmakingTaskCreate && request.Task != MatchmakingTaskUpdate {
		return request, nil
	}
	if len(username) > maxMatchmakingTextBytes {
		return MatchmakingRequest{}, ErrMatchmakingIdentity
	}
	request.Info.Attributes.AppStringAt130 = username
	return request, nil
}

func parseMatchmakingRequest(payload []byte, seed uint32) (MatchmakingRequest, error) {
	reader := bitdemon.NewByteReader(payload, true)
	task, err := reader.ReadUint8()
	if err != nil {
		return MatchmakingRequest{}, malformedMatchmaking("read task", err)
	}
	request := MatchmakingRequest{Task: task}
	switch task {
	case MatchmakingTaskCreate:
		request.Info, err = readMatchmakingRequestInfo(reader)
	case MatchmakingTaskUpdate:
		request.SessionID, err = readMatchmakingSessionID(reader)
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read update session ID", err)
		}
		request.Info, err = readMatchmakingRequestInfo(reader)
	case MatchmakingTaskDelete:
		request.SessionID, err = readMatchmakingSessionID(reader)
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read delete session ID", err)
		}
	case MatchmakingTaskFind:
		request.NumParams, err = reader.ReadUint32()
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read find parameter count", err)
		}
		request.Offset, err = reader.ReadUint32()
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read find result offset", err)
		}
		request.MaxResults, err = reader.ReadUint32()
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read find result limit", err)
		}
		if request.NumParams != 1 || request.MaxResults > maxFindResults {
			return MatchmakingRequest{}, ErrUnsupportedMatchmakingQuery
		}
		request.Query.AttributeHash, err = reader.ReadUint32()
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read find attribute hash", err)
		}
		request.Query.AttributeValue, err = reader.ReadInt32()
		if err != nil {
			return MatchmakingRequest{}, malformedMatchmaking("read find attribute value", err)
		}
	default:
		return MatchmakingRequest{}, fmt.Errorf("%w: %d", ErrUnsupportedMatchmakingTask, task)
	}
	if err != nil {
		return MatchmakingRequest{}, malformedMatchmaking("read task arguments", err)
	}
	padding, err := reader.ReadRaw(uint32(reader.Remaining()))
	if err != nil || !validClientRequestPadding(padding, seed) {
		return MatchmakingRequest{}, malformedMatchmaking("invalid request padding", err)
	}
	return request, nil
}

func readMatchmakingRequestInfo(reader *bitdemon.ByteReader) (MatchmakingInfo, error) {
	hostAddress, err := reader.ReadBlob(maxHostAddressSize)
	if err != nil {
		return MatchmakingInfo{}, fmt.Errorf("read host address: %w", err)
	}
	gameType, err := reader.ReadUint32()
	if err != nil {
		return MatchmakingInfo{}, fmt.Errorf("read game type: %w", err)
	}
	maxPlayers, err := reader.ReadUint32()
	if err != nil {
		return MatchmakingInfo{}, fmt.Errorf("read maximum players: %w", err)
	}
	attributes, err := readMatchmakingAttributes(reader)
	if err != nil {
		return MatchmakingInfo{}, fmt.Errorf("read attributes: %w", err)
	}
	return MatchmakingInfo{
		HostAddress: hostAddress,
		GameType:    gameType,
		MaxPlayers:  maxPlayers,
		Attributes:  attributes,
	}, nil
}

func readMatchmakingAttributes(reader *bitdemon.ByteReader) (MatchmakingAttributes, error) {
	var attributes MatchmakingAttributes
	var err error
	if attributes.AppU32At11C, err = reader.ReadUint32(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x11c: %w", err)
	}
	if attributes.AppU32At120, err = reader.ReadUint32(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x120: %w", err)
	}
	if attributes.AppU64At128, err = reader.ReadUint64(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x128: %w", err)
	}
	if attributes.AppStringAt130, err = reader.ReadString(maxMatchmakingTextBytes); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x130: %w", err)
	}
	if attributes.AppU32At154, err = reader.ReadUint32(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x154: %w", err)
	}
	if attributes.AppU32At158, err = reader.ReadUint32(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x158: %w", err)
	}
	if attributes.AppI32At15C, err = reader.ReadInt32(); err != nil {
		return MatchmakingAttributes{}, fmt.Errorf("read field 0x15c: %w", err)
	}
	return attributes, nil
}

func readMatchmakingSessionID(reader *bitdemon.ByteReader) (MatchmakingSessionID, error) {
	encoded, err := reader.ReadBlob(matchmakingSessionIDSize)
	if err != nil {
		return MatchmakingSessionID{}, err
	}
	if len(encoded) != matchmakingSessionIDSize {
		return MatchmakingSessionID{}, fmt.Errorf("session ID is %d bytes, want %d", len(encoded), matchmakingSessionIDSize)
	}
	var sessionID MatchmakingSessionID
	copy(sessionID[:], encoded)
	return sessionID, nil
}

func writeMatchmakingSessionID(writer *bitdemon.ByteWriter, sessionID MatchmakingSessionID) error {
	return writer.WriteBlob(sessionID[:])
}

func writeMatchmakingResult(writer *bitdemon.ByteWriter, info MatchmakingInfo) error {
	if len(info.HostAddress) > maxHostAddressSize || len(info.Attributes.AppStringAt130) > maxMatchmakingTextBytes {
		return ErrMalformedMatchmakingRequest
	}
	if err := writer.WriteBlob(info.HostAddress); err != nil {
		return err
	}
	if err := writeMatchmakingSessionID(writer, info.SessionID); err != nil {
		return err
	}
	writer.WriteUint32(info.GameType)
	writer.WriteUint32(info.MaxPlayers)
	writer.WriteUint32(info.NumPlayers)
	writer.WriteUint32(info.Attributes.AppU32At11C)
	writer.WriteUint32(info.Attributes.AppU32At120)
	writer.WriteUint64(info.Attributes.AppU64At128)
	if err := writer.WriteString(info.Attributes.AppStringAt130); err != nil {
		return err
	}
	writer.WriteUint32(info.Attributes.AppU32At154)
	writer.WriteUint32(info.Attributes.AppU32At158)
	writer.WriteInt32(info.Attributes.AppI32At15C)
	return nil
}

func malformedMatchmaking(step string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrMalformedMatchmakingRequest, step)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedMatchmakingRequest, step, err)
}
