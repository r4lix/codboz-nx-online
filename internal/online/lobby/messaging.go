package lobby

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	MessagingServiceID                    byte   = 0x06
	MessagingTaskSendGlobalInstantMessage byte   = 0x0e
	globalInstantMessageEvent             uint32 = 21
	maxMessagingMessageBytes                     = 4096
	maxMessagingSenderNameBytes                  = 63
	serverReplySignature                  uint32 = 0xdeadbeef
	pushMessageType                       byte   = 0x02
)

var (
	ErrMalformedMessagingRequest   = errors.New("lobby: malformed messaging request")
	ErrUnsupportedMessagingTask    = errors.New("lobby: unsupported messaging task")
	ErrInvalidGlobalInstantMessage = errors.New("lobby: invalid global instant message")
)

type MessagingRequest struct {
	Task      byte
	Recipient uint64
	Message   []byte
}

func parseMessagingRequest(payload []byte, seed uint32) (MessagingRequest, error) {
	if (len(payload)+bitdemon.TruncatedHMACSize+1)%bitdemon.TripleDESBlockSize != 0 {
		return MessagingRequest{}, fmt.Errorf("%w: invalid encrypted-block padding", ErrMalformedMessagingRequest)
	}

	reader := bitdemon.NewByteReader(payload, true)
	task, err := reader.ReadUint8()
	if err != nil {
		return MessagingRequest{}, malformedMessaging("read task", err)
	}
	if task != MessagingTaskSendGlobalInstantMessage {
		return MessagingRequest{}, fmt.Errorf("%w: %d", ErrUnsupportedMessagingTask, task)
	}
	recipientID, err := reader.ReadUint64()
	if err != nil {
		return MessagingRequest{}, malformedMessaging("read recipient", err)
	}
	message, err := reader.ReadBlob(maxMessagingMessageBytes)
	if err != nil {
		return MessagingRequest{}, malformedMessaging("read message", err)
	}
	if reader.Remaining() > bitdemon.TripleDESBlockSize {
		return MessagingRequest{}, malformedMessaging("excess padding", nil)
	}
	padding, err := reader.ReadRaw(uint32(reader.Remaining()))
	if err != nil || !validClientRequestPadding(padding, seed) {
		return MessagingRequest{}, malformedMessaging("invalid request padding", err)
	}
	return MessagingRequest{Task: task, Recipient: recipientID, Message: message}, nil
}

func marshalGlobalInstantMessagePush(
	sessionKey [bitdemon.SessionKeySize]byte,
	seed uint32,
	senderID uint64,
	senderName string,
	message []byte,
) ([]byte, error) {
	if len(senderName) > maxMessagingSenderNameBytes ||
		strings.IndexByte(senderName, 0) >= 0 ||
		len(message) > maxMessagingMessageBytes {
		return nil, ErrInvalidGlobalInstantMessage
	}

	writer := bitdemon.NewByteWriter(true)
	writer.WriteUint32(globalInstantMessageEvent)
	writer.WriteUint64(senderID)
	if err := writer.WriteString(senderName); err != nil {
		return nil, fmt.Errorf("%w: sender name: %v", ErrInvalidGlobalInstantMessage, err)
	}
	if err := writer.WriteBlob(message); err != nil {
		return nil, fmt.Errorf("%w: message: %v", ErrInvalidGlobalInstantMessage, err)
	}

	plaintext := make([]byte, 5)
	binary.LittleEndian.PutUint32(plaintext[:4], serverReplySignature)
	plaintext[4] = pushMessageType
	plaintext = append(plaintext, writer.Bytes()...)
	plaintext = bitdemon.PadTo3DESBlock(plaintext)
	ciphertext, err := bitdemon.Encrypt3DESCBC(sessionKey[:], bitdemon.DeriveIV(seed), plaintext)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted global instant message: %w", err)
	}
	body := make([]byte, encryptedEnvelopeHeaderSize+len(ciphertext))
	body[0] = 1
	binary.LittleEndian.PutUint32(body[1:encryptedEnvelopeHeaderSize], seed)
	copy(body[encryptedEnvelopeHeaderSize:], ciphertext)
	return body, nil
}

func malformedMessaging(step string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrMalformedMessagingRequest, step)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedMessagingRequest, step, err)
}
