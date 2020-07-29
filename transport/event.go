package transport

// Suppported event types
const (
	EventStreamRecv     = "stream_recv"     // Received stream data and readable
	EventStreamStop     = "stream_stop"     // Received stream stop sending
	EventStreamReset    = "stream_reset"    // Received stream reset
	EventStreamComplete = "stream_complete" // All sending data has been acked.
)

// Event is a union structure of all events.
type Event struct {
	Type      string
	StreamID  uint64
	ErrorCode uint64
}

// newEventStreamRecv creates an event where a STREAM frame was received and data is readable.
func newEventStreamRecv(id uint64) Event {
	return Event{
		Type:     EventStreamRecv,
		StreamID: id,
	}
}

// newEventStreamStop creates an event where a STOP_SENDING frame was received.
func newEventStreamStop(id, code uint64) Event {
	return Event{
		Type:      EventStreamStop,
		StreamID:  id,
		ErrorCode: code,
	}
}

// newEventStreamReset creates an event where a RESET_STREAM frame was received.
func newEventStreamReset(id, code uint64) Event {
	return Event{
		Type:      EventStreamReset,
		StreamID:  id,
		ErrorCode: code,
	}
}

// newEventStreamComplete creates an event where all data of the stream has been acked by peer.
func newEventStreamComplete(id uint64) Event {
	return Event{
		Type:     EventStreamComplete,
		StreamID: id,
	}
}
