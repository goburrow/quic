package transport

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"time"
)

// Supported log events
// https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html
const (
	// Packet
	logEventPacketReceived  = "packet_received"
	logEventPacketSent      = "packet_sent"
	logEventPacketDropped   = "packet_dropped"
	logEventPacketLost      = "packet_lost"
	logEventFramesProcessed = "frames_processed"
	// Stream
	logEventStreamStateUpdated = "stream_state_updated"

	// Recovery
	logEventParametersSet    = "parameters_set"
	logEventMetricsUpdated   = "metrics_updated"
	logEventStateUpdated     = "connection_state_updated"
	logEventLossTimerUpdated = "loss_timer_updated"
)

// Packet dropped triggers.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#section-3.3.7
const (
	logTriggerKeyUnavailable      = "key_unavailable"
	logTriggerUnknownConnectionID = "unknown_connection_id"
	logTriggerHeaderParseError    = "header_parse_error"
	logTriggerPayloadDecryptError = "payload_decrypt_error"
	logTriggerUnexpectedPacket    = "unexpected_packet"
	logTriggerDuplicate           = "duplicate"
	logTriggerUnsupportedVersion  = "unsupported_version"
)

// logger logs their state in key=value pairs.
type logger interface {
	log([]byte) []byte
}

// LogEvent is event sent by connection.
// Application must not retain Message as it is from internal buffers.
type LogEvent struct {
	Time    time.Time
	Type    string
	Message []byte
}

// newLogEvent creates a new LogEvent.
func newLogEvent(tm time.Time, tp string) LogEvent {
	return LogEvent{
		Time:    tm,
		Type:    tp,
		Message: newDataBuffer(dataBufferSizes[0])[:0],
	}
}

// AddField adds a key-value field to current event.
// Only limited types of v are supported.
func (s *LogEvent) addField(k string, v interface{}) {
	s.Message = appendField(s.Message, k, v)
}

func (s *LogEvent) resetMessage() {
	s.Message = s.Message[:0]
}

func (s LogEvent) String() string {
	w := bytes.Buffer{}
	w.WriteString(s.Time.Format(time.RFC3339))
	w.WriteString(" ")
	w.WriteString(s.Type)
	w.WriteString(" ")
	w.Write(s.Message)
	return w.String()
}

func freeLogEvent(e LogEvent) {
	freeDataBuffer(e.Message)
}

func appendField(b []byte, key string, val interface{}) []byte {
	if len(b) > 0 {
		b = append(b, ' ')
	}
	b = append(b, key...)
	b = append(b, '=')
	return appendFieldValue(b, val)
}

func appendFieldValue(b []byte, val interface{}) []byte {
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
	case []uint32:
		b = append(b, '[')
		for i, v := range val {
			if i > 0 {
				b = append(b, ',')
			}
			b = strconv.AppendUint(b, uint64(v), 10)
		}
		b = append(b, ']')
	case time.Duration:
		b = strconv.AppendInt(b, int64(val/time.Millisecond), 10)
	case rangeSet:
		b = append(b, '[')
		for i, v := range val {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, '[')
			b = strconv.AppendUint(b, v.start, 10)
			b = append(b, ',')
			b = strconv.AppendUint(b, v.end, 10)
			b = append(b, ']')
		}
		b = append(b, ']')
	default:
		b = append(b, "<unsupported_type>"...)
	}
	return b
}

// Log connection state

func logConnectionState(e *LogEvent, old, new connectionState) {
	e.addField("old", old.String())
	e.addField("new", new.String())
}

// Log packets

func logPacket(e *LogEvent, s *packet) {
	e.Message = s.log(e.Message)
}

func logParameters(e *LogEvent, p *Parameters) {
	e.addField("owner", "remote") // Log peer's parameters only
	e.Message = p.log(e.Message)
}

// Log frames

// FIXME: Even all frames implement logger interface, we still use
// type check here to avoid moving f to heap.
func logFrame(e *LogEvent, f frame) {
	switch f := f.(type) {
	case *paddingFrame:
		e.Message = f.log(e.Message)
	case *pingFrame:
		e.Message = f.log(e.Message)
	case *ackFrame:
		e.Message = f.log(e.Message)
	case *resetStreamFrame:
		e.Message = f.log(e.Message)
	case *stopSendingFrame:
		e.Message = f.log(e.Message)
	case *cryptoFrame:
		e.Message = f.log(e.Message)
	case *newTokenFrame:
		e.Message = f.log(e.Message)
	case *streamFrame:
		e.Message = f.log(e.Message)
	case *maxDataFrame:
		e.Message = f.log(e.Message)
	case *maxStreamDataFrame:
		e.Message = f.log(e.Message)
	case *maxStreamsFrame:
		e.Message = f.log(e.Message)
	case *dataBlockedFrame:
		e.Message = f.log(e.Message)
	case *streamDataBlockedFrame:
		e.Message = f.log(e.Message)
	case *streamsBlockedFrame:
		e.Message = f.log(e.Message)
	case *newConnectionIDFrame:
		e.Message = f.log(e.Message)
	case *retireConnectionIDFrame:
		e.Message = f.log(e.Message)
	case *pathChallengeFrame:
		e.Message = f.log(e.Message)
	case *pathResponseFrame:
		e.Message = f.log(e.Message)
	case *connectionCloseFrame:
		e.Message = f.log(e.Message)
	case *handshakeDoneFrame:
		e.Message = f.log(e.Message)
	case *datagramFrame:
		e.Message = f.log(e.Message)
	}
}

// Recovery

func logRecovery(e *LogEvent, s *lossRecovery) {
	e.Message = s.log(e.Message)
}

func logLossTimer(e *LogEvent, s *lossRecovery) {
	e.Message = s.logLossTimer(e.Message, e.Time)
}

func logStreamClosed(e *LogEvent, id uint64) {
	e.addField("stream_id", id)
	e.addField("new", "closed")
}
