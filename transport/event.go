package transport

// Suppported event types
const (
	EventStreamReadable = "stream_readable" // Received stream data and readable
	EventStreamWritable = "stream_writable" // Stream is unblocked and can add more data
	EventStreamStop     = "stream_stop"     // Received stream stop sending
	EventStreamReset    = "stream_reset"    // Received stream reset
	EventStreamComplete = "stream_complete" // All sending data has been acked.
)

// Event is a union structure of all events.
type Event struct {
	Type string // Type of event
	ID   uint64 // ID associated with the event. For stream events, this is Stream ID.
	Data uint64 // Additional event data, like ErrorCode.
}

// newEventStreamReadable creates an event where a STREAM frame was received and data is readable.
func newEventStreamReadable(id uint64) Event {
	return Event{
		Type: EventStreamReadable,
		ID:   id,
	}
}

// newEventStreamWritable creates an event where the stream is available to add more data.
func newEventStreamWritable(id uint64) Event {
	return Event{
		Type: EventStreamWritable,
		ID:   id,
	}
}

// newEventStreamStop creates an event where a STOP_SENDING frame was received.
func newEventStreamStop(id, code uint64) Event {
	return Event{
		Type: EventStreamStop,
		ID:   id,
		Data: code,
	}
}

// newEventStreamReset creates an event where a RESET_STREAM frame was received.
func newEventStreamReset(id, code uint64) Event {
	return Event{
		Type: EventStreamReset,
		ID:   id,
		Data: code,
	}
}

// newEventStreamComplete creates an event where all data of the stream has been acked by peer.
func newEventStreamComplete(id uint64) Event {
	return Event{
		Type: EventStreamComplete,
		ID:   id,
	}
}
