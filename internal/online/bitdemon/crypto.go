package bitdemon

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	SessionKeySize     = 24
	TripleDESBlockSize = des.BlockSize
	TruncatedHMACSize  = 4
)

var (
	ErrInvalidSessionKey  = errors.New("bitdemon session key must contain exactly 24 bytes")
	ErrInvalidBlockLength = errors.New("bitdemon 3DES input length must be a multiple of 8 bytes")
)

func DeriveIV(counter uint32) [TripleDESBlockSize]byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], counter)
	digest := Tiger192(encoded[:])
	var iv [TripleDESBlockSize]byte
	copy(iv[:], digest[:TripleDESBlockSize])
	return iv
}

func TruncatedHMACSHA1(key, payload []byte) [TruncatedHMACSize]byte {
	hash := hmac.New(sha1.New, key)
	_, _ = hash.Write(payload)
	sum := hash.Sum(nil)
	var result [TruncatedHMACSize]byte
	copy(result[:], sum[:TruncatedHMACSize])
	return result
}

func Encrypt3DESCBC(key []byte, iv [TripleDESBlockSize]byte, plaintext []byte) ([]byte, error) {
	block, err := newTripleDES(key, len(plaintext))
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func Decrypt3DESCBC(key []byte, iv [TripleDESBlockSize]byte, ciphertext []byte) ([]byte, error) {
	block, err := newTripleDES(key, len(ciphertext))
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func PadTo3DESBlock(payload []byte) []byte {
	paddedLength := (len(payload) + TripleDESBlockSize - 1) &^ (TripleDESBlockSize - 1)
	result := make([]byte, paddedLength)
	copy(result, payload)
	return result
}

func newTripleDES(key []byte, payloadLength int) (cipher.Block, error) {
	if len(key) != SessionKeySize {
		return nil, fmt.Errorf("%w: received %d bytes", ErrInvalidSessionKey, len(key))
	}
	if payloadLength%TripleDESBlockSize != 0 {
		return nil, fmt.Errorf("%w: received %d bytes", ErrInvalidBlockLength, payloadLength)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create bitdemon 3DES cipher: %w", err)
	}
	return block, nil
}
