package lobby

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Producdevity/cod-boz-netplay/internal/online/bitdemon"
)

const encryptedEnvelopeHeaderSize = 5

const reservedClearTaskReplyBodySize = 200

var (
	ErrMalformedEncryptedEnvelope = errors.New("lobby: malformed encrypted envelope")
	ErrInvalidRequestHMAC         = errors.New("lobby: invalid request HMAC")
)

type encryptedRequest struct {
	Seed    uint32
	Service byte
	Payload []byte
}

func marshalClearTaskReplyBody(logicalReply []byte) []byte {
	body := make([]byte, 1, 1+len(logicalReply)+1)
	body = append(body, logicalReply...)
	if len(body) == reservedClearTaskReplyBodySize {
		body = append(body, 0)
	}
	return body
}

func decryptRequestBody(body []byte, sessionKey [bitdemon.SessionKeySize]byte) (encryptedRequest, error) {
	if len(body) < encryptedEnvelopeHeaderSize+bitdemon.TripleDESBlockSize || body[0] != 1 {
		return encryptedRequest{}, ErrMalformedEncryptedEnvelope
	}
	ciphertext := body[encryptedEnvelopeHeaderSize:]
	if len(ciphertext)%bitdemon.TripleDESBlockSize != 0 {
		return encryptedRequest{}, ErrMalformedEncryptedEnvelope
	}
	seed := binary.LittleEndian.Uint32(body[1:encryptedEnvelopeHeaderSize])
	plaintext, err := bitdemon.Decrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(seed), ciphertext)
	if err != nil {
		return encryptedRequest{}, fmt.Errorf("%w: %v", ErrMalformedEncryptedEnvelope, err)
	}
	if len(plaintext) < bitdemon.TruncatedHMACSize+1 {
		return encryptedRequest{}, ErrMalformedEncryptedEnvelope
	}
	wantHMAC := bitdemon.TruncatedHMACSHA1(sessionKey[:], plaintext[bitdemon.TruncatedHMACSize+1:])
	if subtle.ConstantTimeCompare(plaintext[:bitdemon.TruncatedHMACSize], wantHMAC[:]) != 1 {
		return encryptedRequest{}, ErrInvalidRequestHMAC
	}
	return encryptedRequest{
		Seed:    seed,
		Service: plaintext[bitdemon.TruncatedHMACSize],
		Payload: append([]byte(nil), plaintext[bitdemon.TruncatedHMACSize+1:]...),
	}, nil
}

func validClientRequestPadding(padding []byte, seed uint32) bool {
	if len(padding) < 1 || len(padding) > bitdemon.TripleDESBlockSize || padding[0] != 0 {
		return false
	}
	fill := byte(seed)
	for _, value := range padding[1:] {
		if value != fill {
			return false
		}
	}
	return true
}
