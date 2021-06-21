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

const (
	logTriggerKeyUnavailable      = "key_unavailable"
	logTriggerUnknownConnectionID = "unknown_connection_id"
	logTriggerHeaderDecryptError  = "header_decrypt_error"
	logTriggerPayloadDecryptError = "payload_decrypt_error"
	logTriggerUnexpectedPacket    = "unexpected_packet"
	logTriggerDuplicate           = "duplicate"
	logTriggerUnsupportedVersion  = "unsupported_version"
)

// LogEvent is event sent by connection
type LogEvent struct {
	Time   time.Time
	Type   string
	Fields []LogField
}

// newLogEvent creates a new LogEvent.
func newLogEvent(tm time.Time, tp string) LogEvent {
	return LogEvent{
		Time:   tm,
		Type:   tp,
		Fields: make([]LogField, 0, 8),
	}
}

// AddField adds a key-value field to current event.
// Only limited types of v are supported.
func (s *LogEvent) addField(k string, v interface{}) {
	s.Fields = append(s.Fields, newLogField(k, v))
}

func (s *LogEvent) resetFields() {
	s.Fields = s.Fields[:0]
}

func (s LogEvent) String() string {
	w := bytes.Buffer{}
	w.WriteString(s.Time.Format(time.RFC3339))
	w.WriteString(" ")
	w.WriteString(s.Type)
	for _, f := range s.Fields {
		w.WriteString(" ")
		w.WriteString(f.String())
	}
	return w.String()
}

// LogField represents a number or string value.
type LogField struct {
	Key string // Field name
	Str string // String value
	Num uint64 // Number value
}

func newLogField(key string, val interface{}) LogField {
	s := LogField{
		Key: key,
	}
	switch val := val.(type) {
	case int:
		s.Num = uint64(val)
	case int8:
		s.Num = uint64(val)
	case int16:
		s.Num = uint64(val)
	case int32:
		s.Num = uint64(val)
	case int64:
		s.Num = uint64(val)
	case uint:
		s.Num = uint64(val)
	case uint8:
		s.Num = uint64(val)
	case uint16:
		s.Num = uint64(val)
	case uint32:
		s.Num = uint64(val)
	case uint64:
		s.Num = val
	case bool:
		s.Str = strconv.FormatBool(val)
	case string:
		s.Str = val
	case []byte:
		s.Str = hex.EncodeToString(val)
	case []uint32:
		b := make([]byte, 0, 32)
		b = append(b, '[')
		for i, v := range val {
			if i > 0 {
				b = append(b, ',')
			}
			b = strconv.AppendUint(b, uint64(v), 10)
		}
		b = append(b, ']')
		s.Str = string(b)
	case time.Duration:
		s.Num = uint64(val / time.Millisecond)
	case rangeSet:
		b := make([]byte, 0, 32)
		b = append(b, '[')
		for i, v := range val {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, '[')
			b = strconv.AppendUint(b, uint64(v.start), 10)
			b = append(b, ',')
			b = strconv.AppendUint(b, uint64(v.end), 10)
			b = append(b, ']')
		}
		b = append(b, ']')
		s.Str = string(b)
	default:
		s.Str = "<unsupported_type>"
	}
	return s
}

func (s LogField) String() string {
	if s.Str == "" {
		return sprint(s.Key, "=", s.Num)
	}
	return s.Key + "=" + s.Str
}

// Log connection state

func logConnectionState(e *LogEvent, old, new connectionState) {
	e.addField("old", old.String())
	e.addField("new", new.String())
}

// Log packets

func logPacket(e *LogEvent, s *packet) {
	e.addField("packet_type", s.typ.String())
	// Header
	if s.header.version > 0 {
		e.addField("version", s.header.version)
	}
	if len(s.header.dcid) > 0 {
		e.addField("dcid", s.header.dcid)
	}
	if len(s.header.scid) > 0 {
		e.addField("scid", s.header.scid)
	}
	e.addField("packet_number", s.packetNumber)
	if s.packetSize > 0 {
		e.addField("packet_size", s.packetSize)
	}
	if s.payloadLen > 0 {
		e.addField("payload_length", s.payloadLen)
	}
	// Additional info
	if len(s.supportedVersions) > 0 {
		e.addField("supported_versions", s.supportedVersions)
	}
	if len(s.token) > 0 {
		e.addField("stateless_reset_token", s.token)
	}
}

func logTrigger(e *LogEvent, trigger string) {
	e.addField("trigger", trigger)
}

func logParameters(e *LogEvent, p *Parameters) {
	e.addField("owner", "remote") // Log peer's parameters only
	if len(p.OriginalDestinationCID) > 0 {
		e.addField("original_connection_id", p.OriginalDestinationCID)
	}
	if p.MaxIdleTimeout > 0 {
		e.addField("max_idle_timeout", p.MaxIdleTimeout)
	}
	if len(p.OriginalDestinationCID) > 0 {
		e.addField("stateless_reset_token", p.StatelessResetToken)
	}
	if p.MaxUDPPayloadSize > 0 {
		e.addField("max_udp_payload_size", p.MaxUDPPayloadSize)
	}
	if p.InitialMaxData > 0 {
		e.addField("initial_max_data", p.InitialMaxData)
	}
	if p.InitialMaxStreamDataBidiLocal > 0 {
		e.addField("initial_max_stream_data_bidi_local", p.InitialMaxStreamDataBidiLocal)
	}
	if p.InitialMaxStreamDataBidiRemote > 0 {
		e.addField("initial_max_stream_data_bidi_remote", p.InitialMaxStreamDataBidiRemote)
	}
	if p.InitialMaxStreamDataUni > 0 {
		e.addField("initial_max_stream_data_uni", p.InitialMaxStreamDataUni)
	}
	if p.InitialMaxStreamsBidi > 0 {
		e.addField("initial_max_streams_bidi", p.InitialMaxStreamsBidi)
	}
	if p.InitialMaxStreamsUni > 0 {
		e.addField("initial_max_streams_uni", p.InitialMaxStreamsUni)
	}
	if p.AckDelayExponent > 0 {
		e.addField("ack_delay_exponent", p.AckDelayExponent)
	}
	if p.MaxAckDelay > 0 {
		e.addField("max_ack_delay", p.MaxAckDelay)
	}
	if p.DisableActiveMigration {
		e.addField("disable_active_migration", p.DisableActiveMigration)
	}
	if p.ActiveConnectionIDLimit > 0 {
		e.addField("active_connection_id_limit", p.ActiveConnectionIDLimit)
	}
	if len(p.InitialSourceCID) > 0 {
		e.addField("initial_source_connection_id", p.InitialSourceCID)
	}
	if len(p.RetrySourceCID) > 0 {
		e.addField("retry_source_connection_id", p.RetrySourceCID)
	}
}

// Log frames

func logFrame(e *LogEvent, f frame) {
	switch f := f.(type) {
	case *paddingFrame:
		logFramePadding(e, f)
	case *pingFrame:
		logFramePing(e, f)
	case *ackFrame:
		logFrameAck(e, f)
	case *resetStreamFrame:
		logFrameResetStream(e, f)
	case *stopSendingFrame:
		logFrameStopSending(e, f)
	case *cryptoFrame:
		logFrameCrypto(e, f)
	case *newTokenFrame:
		logFrameNewToken(e, f)
	case *streamFrame:
		logFrameStream(e, f)
	case *maxDataFrame:
		logFrameMaxData(e, f)
	case *maxStreamDataFrame:
		logFrameMaxStreamData(e, f)
	case *maxStreamsFrame:
		logFrameMaxStreams(e, f)
	case *dataBlockedFrame:
		logFrameDataBlocked(e, f)
	case *streamDataBlockedFrame:
		logFrameStreamDataBlocked(e, f)
	case *streamsBlockedFrame:
		logFrameStreamsBlocked(e, f)
	case *newConnectionIDFrame:
		logFrameNewConnectionID(e, f)
	case *retireConnectionIDFrame:
		logFrameRetireConnectionID(e, f)
	case *pathChallengeFrame:
		logFramePathChallenge(e, f)
	case *pathResponseFrame:
		logFramePathResponse(e, f)
	case *connectionCloseFrame:
		logFrameConnectionClose(e, f)
	case *handshakeDoneFrame:
		logFrameHandshakeDone(e, f)
	case *datagramFrame:
		logFrameDatagram(e, f)
	}
}

func logFramePadding(e *LogEvent, s *paddingFrame) {
	e.addField("frame_type", "padding")
}

func logFramePing(e *LogEvent, s *pingFrame) {
	e.addField("frame_type", "ping")
}

func logFrameAck(e *LogEvent, s *ackFrame) {
	e.addField("frame_type", "ack")
	e.addField("ack_delay", s.ackDelay)
	e.addField("acked_ranges", s.toRangeSet())
	if s.ecnCounts != nil {
		e.addField("ect0", s.ecnCounts.ect0Count)
		e.addField("ect1", s.ecnCounts.ect1Count)
		e.addField("ce", s.ecnCounts.ceCount)
	}
}

func logFrameResetStream(e *LogEvent, s *resetStreamFrame) {
	e.addField("frame_type", "reset_stream")
	e.addField("stream_id", s.streamID)
	e.addField("error_code", s.errorCode)
	e.addField("final_size", s.finalSize)
}

func logFrameStopSending(e *LogEvent, s *stopSendingFrame) {
	e.addField("frame_type", "stop_sending")
	e.addField("stream_id", s.streamID)
	e.addField("error_code", s.errorCode)
}

func logFrameCrypto(e *LogEvent, s *cryptoFrame) {
	e.addField("frame_type", "crypto")
	e.addField("offset", s.offset)
	e.addField("length", len(s.data))
}

func logFrameNewToken(e *LogEvent, s *newTokenFrame) {
	e.addField("frame_type", "new_token")
	e.addField("token", s.token)
}

func logFrameStream(e *LogEvent, s *streamFrame) {
	e.addField("frame_type", "stream")
	e.addField("stream_id", s.streamID)
	e.addField("offset", s.offset)
	e.addField("length", len(s.data))
	e.addField("fin", s.fin)
}

func logFrameMaxData(e *LogEvent, s *maxDataFrame) {
	e.addField("frame_type", "max_data")
	e.addField("maximum", s.maximumData)
}

func logFrameMaxStreamData(e *LogEvent, s *maxStreamDataFrame) {
	e.addField("frame_type", "max_stream_data")
	e.addField("stream_id", s.streamID)
	e.addField("maximum", s.maximumData)
}

func logFrameMaxStreams(e *LogEvent, s *maxStreamsFrame) {
	e.addField("frame_type", "max_streams")
	if s.bidi {
		e.addField("stream_type", "bidirectional")
	} else {
		e.addField("stream_type", "unidirectional")
	}
	e.addField("maximum", s.maximumStreams)
}

func logFrameDataBlocked(e *LogEvent, s *dataBlockedFrame) {
	e.addField("frame_type", "data_blocked")
	e.addField("limit", s.dataLimit)
}

func logFrameStreamDataBlocked(e *LogEvent, s *streamDataBlockedFrame) {
	e.addField("frame_type", "stream_data_blocked")
	e.addField("stream_id", s.streamID)
	e.addField("limit", s.dataLimit)
}

func logFrameStreamsBlocked(e *LogEvent, s *streamsBlockedFrame) {
	e.addField("frame_type", "streams_blocked")
	if s.bidi {
		e.addField("stream_type", "bidirectional")
	} else {
		e.addField("stream_type", "unidirectional")
	}
	e.addField("limit", s.streamLimit)
}

func logFrameNewConnectionID(e *LogEvent, s *newConnectionIDFrame) {
	e.addField("frame_type", "new_connection_id")
	e.addField("sequence_number", s.sequenceNumber)
	e.addField("retire_prior_to", s.retirePriorTo)
	e.addField("connection_id", s.connectionID)
	e.addField("stateless_reset_token", s.statelessResetToken)
}

func logFrameRetireConnectionID(e *LogEvent, s *retireConnectionIDFrame) {
	e.addField("frame_type", "retire_connection_id")
	e.addField("sequence_number", s.sequenceNumber)
}

func logFramePathChallenge(e *LogEvent, s *pathChallengeFrame) {
	e.addField("frame_type", "path_challenge")
	e.addField("data", s.data)
}

func logFramePathResponse(e *LogEvent, s *pathResponseFrame) {
	e.addField("frame_type", "path_response")
	e.addField("data", s.data)
}

func logFrameConnectionClose(e *LogEvent, s *connectionCloseFrame) {
	e.addField("frame_type", "connection_close")
	if s.application {
		e.addField("error_space", "application")
	} else {
		e.addField("error_space", "transport")
	}
	e.addField("error_code", errorCodeString(s.errorCode))
	e.addField("raw_error_code", s.errorCode)
	if s.frameType > 0 {
		e.addField("trigger_frame_type", s.frameType)
	}
	e.addField("reason", string(s.reasonPhrase))
}

func logFrameHandshakeDone(e *LogEvent, s *handshakeDoneFrame) {
	e.addField("frame_type", "handshake_done")
}

func logFrameDatagram(e *LogEvent, s *datagramFrame) {
	e.addField("frame_type", "datagram")
	e.addField("length", len(s.data))
}

// Recovery

func logRecovery(e *LogEvent, s *lossRecovery) {
	// Loss detection
	e.addField("min_rtt", s.minRTT)
	e.addField("smoothed_rtt", s.roundTripTime())
	e.addField("latest_rtt", s.latestRTT)
	e.addField("rtt_variance", s.rttVariance)
	e.addField("pto_count", s.ptoCount)
	// Congestion control
	e.addField("congestion_window", s.congestion.congestionWindow)
	e.addField("bytes_in_flight", s.congestion.bytesInFlight)
}

func logLossTimer(e *LogEvent, s *lossRecovery) {
	if s.lossDetectionTimer.IsZero() {
		e.addField("event_type", "cancelled")
	} else if s.lossDetectionTimer.Before(e.Time) {
		e.addField("event_type", "set")
		e.addField("delta", "0")
	} else {
		e.addField("event_type", "set")
		e.addField("delta", s.lossDetectionTimer.Sub(e.Time))
	}
}

func logStreamClosed(e *LogEvent, id uint64) {
	e.addField("stream_id", id)
	e.addField("new", "closed")
}
