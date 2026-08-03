// Package auth implements BOZ account creation and lobby tickets.
package auth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	BOZTitleID = 18436

	MessageCreateAccountRequest byte = 0x00
	MessageCreateAccountReply   byte = 0x01

	StatusNoError              Status = 700
	StatusCreateUsernameExists Status = 707

	createAccountBodySize  = 116
	createAccountBlockSize = 96
	accountUsernameSize    = 64
	accountPasswordSize    = 24
	accountBlockSignature  = 0xefbdadde
)

var (
	ErrMalformedMessage       = errors.New("auth: malformed message")
	ErrEncryptedCreateAccount = errors.New("auth: create-account request must be cleartext")
	ErrUnexpectedMessageType  = errors.New("auth: unexpected message type")
	ErrTypeCheckingRequired   = errors.New("auth: type checking is required")
	ErrUnexpectedTitle        = errors.New("auth: unexpected title ID")
	ErrUnsupportedLicenseHash = errors.New("auth: unsupported license hash")
	ErrInvalidAccountBlock    = errors.New("auth: invalid account block")
	ErrInvalidUsername        = errors.New("auth: invalid username")
)

var createAccountKey = [bitdemon.SessionKeySize]byte{
	0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type Status uint32

type CreateAccountRequest struct {
	IVSeed       uint32
	TitleID      uint32
	LicenseHash  uint64
	Username     string
	PasswordHash [accountPasswordSize]byte
}

// ParseCreateAccountBody parses a BOZ generic-account request.
func ParseCreateAccountBody(body []byte) (CreateAccountRequest, error) {
	if len(body) != createAccountBodySize {
		return CreateAccountRequest{}, fmt.Errorf("%w: create-account body is %d bytes, want %d", ErrMalformedMessage, len(body), createAccountBodySize)
	}
	if body[0] != 0 {
		return CreateAccountRequest{}, ErrEncryptedCreateAccount
	}
	if body[1] != MessageCreateAccountRequest {
		return CreateAccountRequest{}, fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrUnexpectedMessageType, body[1], MessageCreateAccountRequest)
	}

	reader := bitdemon.NewBitReader(body[2:])
	typeChecked, err := reader.ReadTypeCheckedFlag()
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: read type-check flag: %v", ErrMalformedMessage, err)
	}
	if !typeChecked {
		return CreateAccountRequest{}, ErrTypeCheckingRequired
	}
	ivSeed, err := reader.ReadUint32()
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: read IV seed: %v", ErrMalformedMessage, err)
	}
	titleID, err := reader.ReadUint32()
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: read title ID: %v", ErrMalformedMessage, err)
	}
	if titleID != BOZTitleID {
		return CreateAccountRequest{}, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedTitle, titleID, BOZTitleID)
	}

	reader.SetTypeChecked(false)
	licenseHash, err := reader.ReadUint64()
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: read license hash: %v", ErrMalformedMessage, err)
	}
	if licenseHash != 0 {
		return CreateAccountRequest{}, fmt.Errorf("%w: 0x%016x", ErrUnsupportedLicenseHash, licenseHash)
	}
	encryptedBlock, err := reader.ReadRaw(createAccountBlockSize)
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: read account block: %v", ErrMalformedMessage, err)
	}
	if reader.RemainingBits() != 5 || body[len(body)-1]&0xf8 != 0 {
		return CreateAccountRequest{}, fmt.Errorf("%w: create-account request has nonzero or unexpected padding", ErrMalformedMessage)
	}

	plaintext, err := bitdemon.Decrypt3DESCBC(createAccountKey[:], bitdemon.DeriveIV(ivSeed), encryptedBlock)
	if err != nil {
		return CreateAccountRequest{}, fmt.Errorf("%w: decrypt account block: %v", ErrInvalidAccountBlock, err)
	}
	if binary.LittleEndian.Uint32(plaintext[0:4]) != accountBlockSignature {
		return CreateAccountRequest{}, ErrInvalidAccountBlock
	}
	username, err := parsePaddedUsername(plaintext[4 : 4+accountUsernameSize])
	if err != nil {
		return CreateAccountRequest{}, err
	}
	if !allZero(plaintext[92:96]) {
		return CreateAccountRequest{}, errors.New("auth: account block has nonzero reserved bytes")
	}

	request := CreateAccountRequest{
		IVSeed:      ivSeed,
		TitleID:     titleID,
		LicenseHash: licenseHash,
		Username:    username,
	}
	copy(request.PasswordHash[:], plaintext[68:92])
	return request, nil
}

func parsePaddedUsername(field []byte) (string, error) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	} else if !allZero(field[end:]) {
		return "", errors.New("auth: username has nonzero bytes after its terminator")
	}
	if end == 0 || !utf8.Valid(field[:end]) {
		return "", ErrInvalidUsername
	}
	for _, character := range field[:end] {
		if character < 0x20 || character > 0x7e {
			return "", ErrInvalidUsername
		}
	}
	return string(field[:end]), nil
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

// MarshalCreateAccountReplyBody returns the cleartext account-creation reply.
func MarshalCreateAccountReplyBody(status Status) []byte {
	return marshalStatusReplyBody(MessageCreateAccountReply, status)
}

func marshalStatusReplyBody(messageType byte, status Status) []byte {
	writer := bitdemon.NewBitWriter(false)
	writer.WriteUint8(messageType)
	writer.SetTypeChecked(true)
	writer.WriteTypeCheckedFlag()
	writer.WriteUint32(uint32(status))
	return append([]byte{0}, writer.Bytes()...)
}
