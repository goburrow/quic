package transport

import (
	"bytes"
	"strconv"
	"time"
)

// Supported log events
// https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html
const (
	// Connection
	logEventConnStateUpdated = "connectivity:connection_state_updated"
	// Packet
	logEventPacketReceived  = "transport:packet_received"
	logEventPacketSent      = "transport:packet_sent"
	logEventPacketDropped   = "transport:packet_dropped"
	logEventPacketLost      = "recovery:packet_lost"
	logEventFramesProcessed = "transport:frames_processed"
	// Stream
	logEventStreamStateUpdated = "transport:stream_state_updated"
	// Recovery
	logEventParametersSet    = "recovery:parameters_set"
	logEventMetricsUpdated   = "recovery:metrics_updated"
	logEventLossTimerUpdated = "recovery:loss_timer_updated"
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

const hexTable = "0123456789abcdef"

// logger logs their state in key=value pairs.
type logger interface {
	log([]byte) []byte
}

// LogEvent is event sent by connection.
// Application must not retain Data as it is from internal buffers.
type LogEvent struct {
	Time time.Time
	Name string
	Data []byte
}

// newLogEvent creates a new LogEvent.
func newLogEvent(tm time.Time, nm string) LogEvent {
	return LogEvent{
		Time: tm,
		Name: nm,
		Data: newDataBuffer(dataBufferSizes[0])[:0],
	}
}

// AddField adds a key-value field to current event.
// Only limited types of v are supported.
func (s *LogEvent) addField(k string, v interface{}) {
	s.Data = appendField(s.Data, k, v)
}

func (s *LogEvent) resetData() {
	s.Data = s.Data[:0]
}

func (s LogEvent) String() string {
	w := bytes.Buffer{}
	w.WriteString(s.Time.Format(time.RFC3339))
	w.WriteString(" ")
	w.WriteString(s.Name)
	w.WriteString(" ")
	w.Write(s.Data)
	return w.String()
}

func freeLogEvent(e LogEvent) {
	freeDataBuffer(e.Data)
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
		for _, v := range val {
			b = append(b, hexTable[v>>4])
			b = append(b, hexTable[v&0x0f])
		}
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
	e.Data = s.log(e.Data)
}

func logParameters(e *LogEvent, p *Parameters) {
	e.addField("owner", "remote") // Log peer's parameters only
	e.Data = p.log(e.Data)
}

// Log frames

// FIXME: Even all frames implement logger interface, we still use
// type check here to avoid moving f to heap.
func logFrame(e *LogEvent, f frame) {
	switch f := f.(type) {
	case *paddingFrame:
		e.Data = f.log(e.Data)
	case *pingFrame:
		e.Data = f.log(e.Data)
	case *ackFrame:
		e.Data = f.log(e.Data)
	case *resetStreamFrame:
		e.Data = f.log(e.Data)
	case *stopSendingFrame:
		e.Data = f.log(e.Data)
	case *cryptoFrame:
		e.Data = f.log(e.Data)
	case *newTokenFrame:
		e.Data = f.log(e.Data)
	case *streamFrame:
		e.Data = f.log(e.Data)
	case *maxDataFrame:
		e.Data = f.log(e.Data)
	case *maxStreamDataFrame:
		e.Data = f.log(e.Data)
	case *maxStreamsFrame:
		e.Data = f.log(e.Data)
	case *dataBlockedFrame:
		e.Data = f.log(e.Data)
	case *streamDataBlockedFrame:
		e.Data = f.log(e.Data)
	case *streamsBlockedFrame:
		e.Data = f.log(e.Data)
	case *newConnectionIDFrame:
		e.Data = f.log(e.Data)
	case *retireConnectionIDFrame:
		e.Data = f.log(e.Data)
	case *pathChallengeFrame:
		e.Data = f.log(e.Data)
	case *pathResponseFrame:
		e.Data = f.log(e.Data)
	case *connectionCloseFrame:
		e.Data = f.log(e.Data)
	case *handshakeDoneFrame:
		e.Data = f.log(e.Data)
	case *datagramFrame:
		e.Data = f.log(e.Data)
	}
}

// Recovery

func logRecovery(e *LogEvent, s *lossRecovery) {
	e.Data = s.log(e.Data)
}

func logLossTimer(e *LogEvent, s *lossRecovery) {
	e.Data = s.logLossTimer(e.Data, e.Time)
}

func logStreamClosed(e *LogEvent, id uint64) {
	e.addField("stream_id", id)
	e.addField("new", "closed")
}
