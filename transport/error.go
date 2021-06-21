package transport

import (
	"encoding/hex"
	"errors"
	"strconv"
)

// https://www.rfc-editor.org/rfc/rfc9000.html#section-20
const (
	NoError                 uint64 = 0x0
	InternalError           uint64 = 0x1
	ConnectionRefused       uint64 = 0x2
	FlowControlError        uint64 = 0x3
	StreamLimitError        uint64 = 0x4
	StreamStateError        uint64 = 0x5
	FinalSizeError          uint64 = 0x6
	FrameEncodingError      uint64 = 0x7
	TransportParameterError uint64 = 0x8
	ConnectionIDLimitError  uint64 = 0x9
	ProtocolViolation       uint64 = 0xa
	InvalidToken            uint64 = 0xb
	ApplicationError        uint64 = 0xc
	CryptoBufferExceeded    uint64 = 0xd
	KeyUpdateError          uint64 = 0xe
	AEADLimitReached        uint64 = 0xf
	CryptoError             uint64 = 0x100
)

var errorText = map[uint64]string{
	NoError:                 "no_error",
	InternalError:           "internal_error",
	ConnectionRefused:       "connection_refused",
	FlowControlError:        "flow_control_error",
	StreamLimitError:        "stream_limit_error",
	StreamStateError:        "stream_state_error",
	FinalSizeError:          "final_size_error",
	FrameEncodingError:      "frame_encoding_error",
	TransportParameterError: "transport_parameter_error",
	ConnectionIDLimitError:  "connection_id_limit_error",
	ProtocolViolation:       "protocol_violation",
	InvalidToken:            "invalid_token",
	ApplicationError:        "application_error",
	CryptoBufferExceeded:    "crypto_buffer_exceeded",
	KeyUpdateError:          "key_update_error",
	AEADLimitReached:        "aead_limit_reached",
	CryptoError:             "crypto_error",
}

func errorCodeString(code uint64) string {
	str := errorText[code]
	if str == "" {
		if code&(^(CryptoError - 1)) == CryptoError {
			str = sprint(errorText[CryptoError], "_", code&(CryptoError-1))
		} else {
			str = sprint(code)
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

func newError(code uint64, msg string) *Error {
	return &Error{
		Code:    code,
		Message: msg,
	}
}

// packetDroppedError is the error returned when received packet is dropped
// due to invalid or corrupted.
type packetDroppedError struct {
	trigger string
}

func (s packetDroppedError) Error() string {
	return "packet_dropped: " + s.trigger
}

func newPacketDroppedError(trigger string) packetDroppedError {
	return packetDroppedError{trigger}
}

// IsPacketDropped returns true (and reason) if err is a packet dropped so
// the packet can either be discarded or bufferred for later use.
// This function should only be used for error returned by Conn.Write.
func IsPacketDropped(err error) (string, bool) {
	if err, ok := err.(packetDroppedError); ok {
		return err.trigger, true
	}
	return "", false
}

var (
	errFinalSize     = newError(FinalSizeError, "")
	errInvalidPacket = newError(FrameEncodingError, "invalid packet")

	errShortBuffer = errors.New("short buffer")
)

// sprint is simpler version fmt.Sprint but does not cause values escaping to heaps.
func sprint(values ...interface{}) string {
	b := make([]byte, 0, 64)
	for _, val := range values {
		switch val := val.(type) {
		case int:
			b = strconv.AppendInt(b, int64(val), 10)
		case int8:
			b = strconv.AppendInt(b, int64(val), 10)
		case int16:
			b = strconv.AppendInt(b, int64(val), 10)
		case int32:
			b = strconv.AppendInt(b, int64(val), 10)
		case int64:
			b = strconv.AppendInt(b, val, 10)
		case uint:
			b = strconv.AppendUint(b, uint64(val), 10)
		case uint8:
			b = strconv.AppendUint(b, uint64(val), 10)
		case uint16:
			b = strconv.AppendUint(b, uint64(val), 10)
		case uint32:
			b = strconv.AppendUint(b, uint64(val), 10)
		case uint64:
			b = strconv.AppendUint(b, val, 10)
		case bool:
			b = strconv.AppendBool(b, val)
		case string:
			b = append(b, val...)
		case []byte:
			n := hex.EncodedLen(len(val))
			b = append(b, make([]byte, n)...)
			hex.Encode(b[len(b)-n:], val)
		case []uint32: // List of quic versions
			b = append(b, '[')
			for i, v := range val {
				if i > 0 {
					b = append(b, ',')
				}
				b = strconv.AppendUint(b, uint64(v), 10)
			}
			b = append(b, ']')
		default:
			b = append(b, '?')
		}
	}
	return string(b)
}
