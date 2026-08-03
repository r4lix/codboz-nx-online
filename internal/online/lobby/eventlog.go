package lobby

import (
	"errors"
	"fmt"

	"github.com/Producdevity/cod-boz-online/internal/online/bitdemon"
)

const (
	EventLogServiceID byte = 0x43
	EventLogTaskLog   byte = 0x02

	defaultMaxEventBlob = 64 << 10
	taskReplyMessage    = 0x01
	statusNoError       = 0
)

var (
	ErrMalformedEventLogRequest = errors.New("lobby: malformed EventLog request")
	ErrUnsupportedEventLogTask  = errors.New("lobby: unsupported EventLog task")
)

type EventLogRequest struct {
	Task     byte
	Blob     []byte
	Category uint32
}

func parseEventLogRequest(payload []byte, seed uint32) (EventLogRequest, error) {
	reader := bitdemon.NewByteReader(payload, true)
	task, err := reader.ReadUint8()
	if err != nil {
		return EventLogRequest{}, fmt.Errorf("%w: read task: %v", ErrMalformedEventLogRequest, err)
	}
	if task != EventLogTaskLog {
		return EventLogRequest{}, fmt.Errorf("%w: %d", ErrUnsupportedEventLogTask, task)
	}
	blob, err := reader.ReadBlob(defaultMaxEventBlob)
	if err != nil {
		return EventLogRequest{}, fmt.Errorf("%w: read event blob: %v", ErrMalformedEventLogRequest, err)
	}
	category, err := reader.ReadUint32()
	if err != nil {
		return EventLogRequest{}, fmt.Errorf("%w: read category: %v", ErrMalformedEventLogRequest, err)
	}
	padding, err := reader.ReadRaw(uint32(reader.Remaining()))
	if err != nil || !validClientRequestPadding(padding, seed) {
		return EventLogRequest{}, fmt.Errorf("%w: invalid request padding", ErrMalformedEventLogRequest)
	}
	return EventLogRequest{Task: task, Blob: blob, Category: category}, nil
}

func marshalTaskReply(transactionID uint64, operation byte, errorCode, resultCount, totalResultCount uint32) []byte {
	writer := bitdemon.NewByteWriter(true)
	writer.WriteRaw([]byte{taskReplyMessage})
	writer.WriteUint64(transactionID)
	writer.WriteUint32(errorCode)
	writer.WriteUint8(operation)
	writer.WriteUint32(resultCount)
	if resultCount != 0 {
		writer.WriteUint32(totalResultCount)
	}
	return writer.Bytes()
}
