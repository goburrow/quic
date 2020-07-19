package transport

// Suppported event types
const (
	EventStream         = "stream"
	EventStopSending    = "stop_sending"
	EventResetStream    = "reset_stream"
	EventStreamComplete = "stream_complete"
)

// Event is a union structure of all events.
type Event struct {
	Type      string
	StreamID  uint64
	ErrorCode uint64
}

// newStreamRecvEvent creates an event where a STREAM frame was received and data is readable.
func newStreamRecvEvent(id uint64) Event {
	return Event{
		Type:     EventStream,
		StreamID: id,
	}
}

// newStreamStopEvent creates an event where a STOP_SENDING frame was received.
func newStreamStopEvent(id, code uint64) Event {
	return Event{
		Type:      EventStopSending,
		StreamID:  id,
		ErrorCode: code,
	}
}

// newStreamResetEvent creates an event where a RESET_STREAM frame was received.
func newStreamResetEvent(id, code uint64) Event {
	return Event{
		Type:      EventResetStream,
		StreamID:  id,
		ErrorCode: code,
	}
}

// newStreamComplete creates an event where all data of the stream has been acked by peer.
func newStreamCompleteEvent(id uint64) Event {
	return Event{
		Type:     EventStreamComplete,
		StreamID: id,
	}
}
