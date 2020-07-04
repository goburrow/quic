package transport

import (
	"errors"
	"fmt"
)

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#error-codes
const (
	NoError                 = 0x0
	InternalError           = 0x1
	ConnectionRefused       = 0x2
	FlowControlError        = 0x3
	StreamLimitError        = 0x4
	StreamStateError        = 0x5
	FinalSizeError          = 0x6
	FrameEncodingError      = 0x7
	TransportParameterError = 0x8
	ConnectionIDLimitError  = 0x9
	ProtocolViolation       = 0xa
	InvalidToken            = 0xb
	ApplicationError        = 0xc
	CryptoBufferExceeded    = 0xd
	CryptoError             = 0x100
)

var errorText = map[uint64]string{
	NoError:                 "NO_ERROR",
	InternalError:           "INTERNAL_ERROR",
	ConnectionRefused:       "CONNECTION_REFUSED",
	FlowControlError:        "FLOW_CONTROL_ERROR",
	StreamLimitError:        "STREAM_LIMIT_ERROR",
	StreamStateError:        "STREAM_STATE_ERROR",
	FinalSizeError:          "FINAL_SIZE_ERROR",
	FrameEncodingError:      "FRAME_ENCODING_ERROR",
	TransportParameterError: "TRANSPORT_PARAMETER_ERROR",
	ConnectionIDLimitError:  "CONNECTION_ID_LIMIT_ERROR",
	ProtocolViolation:       "PROTOCOL_VIOLATION",
	InvalidToken:            "INVALID_TOKEN",
	ApplicationError:        "APPLICATION_ERROR",
	CryptoBufferExceeded:    "CRYPTO_BUFFER_EXCEEDED",
	CryptoError:             "CRYPTO_ERROR",
}

func errorCodeString(code uint64) string {
	str := errorText[code]
	if str == "" {
		if code&(^uint64(CryptoError-1)) == CryptoError {
			str = fmt.Sprintf("%s %d", errorText[CryptoError], code&(CryptoError-1))
		} else {
			str = fmt.Sprintf("0x%x", code)
		}
	}
	return str
}

// Error is the QUIC transport error.
type Error struct {
	Code    uint64
	Message string
}

func (e *Error) Error() string {
	code := errorCodeString(e.Code)
	if e.Message == "" {
		return code
	}
	return code + " " + e.Message
}

func newError(code uint64, msg string, v ...interface{}) *Error {
	if len(v) > 0 {
		msg = fmt.Sprintf(msg, v...)
	}
	return &Error{
		Code:    code,
		Message: msg,
	}
}

var (
	errFlowControl   = newError(FlowControlError, "")
	errFinalSize     = newError(FinalSizeError, "")
	errInvalidPacket = newError(FrameEncodingError, "invalid packet")
	errInvalidToken  = newError(InvalidToken, "")

	errShortBuffer = errors.New("ShortBuffer")
)
