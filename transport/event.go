package transport

import "fmt"

// Suppported event types
const (
	EventConnOpen   = "conn_open"   // New connection established.
	EventConnClosed = "conn_closed" // Connection closed.

	EventStreamOpen      = "stream_open"      // A new stream has been opened by peer.
	EventStreamReadable  = "stream_readable"  // Received stream data and readable
	EventStreamWritable  = "stream_writable"  // Stream is unblocked and can add more data
	EventStreamCreatable = "stream_creatable" // Maximum streams increased by peer.

	EventStreamStop     = "stream_stop"     // Received stream stop sending from peer.
	EventStreamReset    = "stream_reset"    // Received stream reset from peer.
	EventStreamComplete = "stream_complete" // All sending data has been acked.
	EventStreamClosed   = "stream_closed"   // Stream is fully closed and no longer available.

	EventDatagramWritable = "datagram_writable" // Datagram is supported by peer.
	EventDatagramReadable = "datagram_readable" // Received datagram.
)

// Event is a union structure of all events.
type Event struct {
	Type string // Type of event
	ID   uint64 // ID associated with the event. For stream events, this is Stream ID.
	Data uint64 // Additional event data, like ErrorCode.
}

func (s Event) String() string {
	if s.Data == 0 {
		return fmt.Sprintf("%s:%d", s.Type, s.ID)
	}
	return fmt.Sprintf("%s:%d(%d)", s.Type, s.ID, s.Data)
}

// newEventStreamOpen creates an event where a connection state is set to Active.
func newEventConnectionOpen() Event {
	return Event{
		Type: EventConnOpen,
	}
}

// newEventConnectionClosed creates an event where a connection state is set to Closed.
func newEventConnectionClosed() Event {
	return Event{
		Type: EventConnClosed,
	}
}

// newEventStreamOpen creates an event where a stream is opened by peer.
func newEventStreamOpen(id uint64, bidi bool) Event {
	e := Event{
		Type: EventStreamOpen,
		ID:   id,
	}
	if bidi {
		e.Data = 1
	}
	return e
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

// newEventStreamWritable creates an event where the stream is available to add more data.
func newEventStreamCreatable(bidi bool) Event {
	e := Event{
		Type: EventStreamCreatable,
	}
	if bidi {
		e.ID = 1
	}
	return e
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

// newEventStreamClosed creates an event where the stream is fully closed and garbage collected.
func newEventStreamClosed(id uint64) Event {
	return Event{
		Type: EventStreamClosed,
		ID:   id,
	}
}

// newEventDatagramWritable creates an event when peer accepts DATAGRAM.
func newEventDatagramWritable(max uint64) Event {
	return Event{
		Type: EventDatagramWritable,
		Data: max,
	}
}

// newEventDatagramReadable creates an event where a DATAGRAM frame was received.
func newEventDatagramReadable() Event {
	return Event{
		Type: EventDatagramReadable,
	}
}
