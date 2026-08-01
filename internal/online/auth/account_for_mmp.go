package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

const (
	MessageAccountForMMPRequest byte = 0x0a
	MessageAccountForMMPReply   byte = 0x0b

	StatusBadAccount Status = 704

	accountForMMPRequestBodySize = 20
	authTicketSize               = 128
	authTicketSignature          = 0xefbdadde
	authTicketTypeUserToService  = 0
)

type AccountForMMPRequest struct {
	IVSeed      uint32
	TitleID     uint32
	AccountHash uint64
}

func ParseAccountForMMPBody(body []byte) (AccountForMMPRequest, error) {
	if len(body) != accountForMMPRequestBodySize {
		return AccountForMMPRequest{}, fmt.Errorf("%w: AccountForMMP body is %d bytes, want %d", ErrMalformedMessage, len(body), accountForMMPRequestBodySize)
	}
	if body[0] != 0 {
		return AccountForMMPRequest{}, errors.New("auth: AccountForMMP request must be cleartext")
	}
	if body[1] != MessageAccountForMMPRequest {
		return AccountForMMPRequest{}, fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrUnexpectedMessageType, body[1], MessageAccountForMMPRequest)
	}
	reader := bitdemon.NewBitReader(body[2:])
	typeChecked, err := reader.ReadTypeCheckedFlag()
	if err != nil {
		return AccountForMMPRequest{}, fmt.Errorf("%w: read type-check flag: %v", ErrMalformedMessage, err)
	}
	if !typeChecked {
		return AccountForMMPRequest{}, ErrTypeCheckingRequired
	}
	seed, err := reader.ReadUint32()
	if err != nil {
		return AccountForMMPRequest{}, fmt.Errorf("%w: read IV seed: %v", ErrMalformedMessage, err)
	}
	titleID, err := reader.ReadUint32()
	if err != nil {
		return AccountForMMPRequest{}, fmt.Errorf("%w: read title ID: %v", ErrMalformedMessage, err)
	}
	if titleID != BOZTitleID {
		return AccountForMMPRequest{}, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedTitle, titleID, BOZTitleID)
	}
	reader.SetTypeChecked(false)
	accountHash, err := reader.ReadUint64()
	if err != nil {
		return AccountForMMPRequest{}, fmt.Errorf("%w: read account hash: %v", ErrMalformedMessage, err)
	}
	if reader.RemainingBits() != 5 || body[len(body)-1]&0xf8 != 0 {
		return AccountForMMPRequest{}, fmt.Errorf("%w: AccountForMMP request has nonzero or unexpected padding", ErrMalformedMessage)
	}
	return AccountForMMPRequest{IVSeed: seed, TitleID: titleID, AccountHash: accountHash}, nil
}

func marshalAccountForMMPErrorBody(status Status) []byte {
	return marshalStatusReplyBody(MessageAccountForMMPReply, status)
}

func marshalAccountForMMPSuccessBody(account Account, ticketSeed uint32, sessionKey [bitdemon.SessionKeySize]byte, issuedAt, expiresAt time.Time) ([]byte, error) {
	ticket, err := buildEncryptedAuthTicket(account, ticketSeed, sessionKey, issuedAt, expiresAt)
	if err != nil {
		return nil, err
	}
	writer := bitdemon.NewBitWriter(false)
	writer.WriteUint8(MessageAccountForMMPReply)
	writer.SetTypeChecked(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(uint32(StatusNoError))
	writer.WriteUint32(ticketSeed)
	writer.SetTypeChecked(false)
	writer.WriteRaw(ticket[:])
	return append([]byte{0}, writer.Bytes()...), nil
}

func buildEncryptedAuthTicket(account Account, ticketSeed uint32, sessionKey [bitdemon.SessionKeySize]byte, issuedAt, expiresAt time.Time) ([authTicketSize]byte, error) {
	issuedUnix := issuedAt.Unix()
	expiresUnix := expiresAt.Unix()
	if issuedUnix < 0 || issuedUnix > math.MaxUint32 || expiresUnix < 0 || expiresUnix > math.MaxUint32 || !expiresAt.After(issuedAt) {
		return [authTicketSize]byte{}, errors.New("auth: ticket time is outside the legacy uint32 range")
	}
	if len(account.Username) > accountUsernameSize {
		return [authTicketSize]byte{}, ErrInvalidUsername
	}

	var plaintext [authTicketSize]byte
	binary.LittleEndian.PutUint32(plaintext[0:4], authTicketSignature)
	plaintext[4] = authTicketTypeUserToService
	binary.LittleEndian.PutUint32(plaintext[5:9], BOZTitleID)
	binary.LittleEndian.PutUint32(plaintext[9:13], uint32(issuedUnix))
	binary.LittleEndian.PutUint32(plaintext[13:17], uint32(expiresUnix))
	binary.LittleEndian.PutUint64(plaintext[17:25], 0)
	binary.LittleEndian.PutUint64(plaintext[25:33], account.UserID)
	copy(plaintext[33:97], account.Username)
	copy(plaintext[97:121], sessionKey[:])

	ciphertext, err := bitdemon.Encrypt3DESCBC(account.PasswordHash[:], bitdemon.DeriveIV(ticketSeed), plaintext[:])
	if err != nil {
		return [authTicketSize]byte{}, fmt.Errorf("auth: encrypt ticket: %w", err)
	}
	var ticket [authTicketSize]byte
	copy(ticket[:], ciphertext)
	return ticket, nil
}
