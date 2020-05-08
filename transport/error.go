package transport

import (
	"errors"
	"fmt"
)

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#error-codes
const (
	NoError                 = 0x0
	InternalError           = 0x1
	ServerBusy              = 0x2
	FlowControlError        = 0x3
	StreamLimitError        = 0x4
	StreamStateError        = 0x5
	FinalSizeError          = 0x6
	FrameEncodingError      = 0x7
	TransportParameterError = 0x8
	ProtocolViolation       = 0xa
	CryptoBufferExceeded    = 0xd
	CryptoError             = 0x100
)

type Error struct {
	Code    uint64
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("0x%x %s", e.Code, e.Message)
	}
	return fmt.Sprintf("0x%x", e.Code)
}

func newError(code uint64, msg string, v ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(msg, v...),
	}
}

var (
	errFlowControl       = newError(FlowControlError, "FlowControl")
	errStreamLimit       = newError(StreamLimitError, "StreamLimit")
	errFinalSize         = newError(FinalSizeError, "FinalSize")
	errInvalidPacket     = newError(FrameEncodingError, "PacketEncoding")
	errInvalidFrame      = newError(FrameEncodingError, "FrameEncoding")
	errProtocolViolation = newError(ProtocolViolation, "ProtocolViolation")

	errShortBuffer = errors.New("ShortBuffer")
)
