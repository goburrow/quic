package transport

import "fmt"

// Suppported event types
const (
	EventConnOpen   = "conn_open"   // New connection established.
	EventConnClosed = "conn_closed" // Connection closed.

	EventStreamOpen      = "stream_open"      // A new stream has been opened by peer.
	EventStreamReadable  = "stream_readable"  // Received stream data and readable or reset by peer.
	EventStreamWritable  = "stream_writable"  // Stream is unblocked and can add more data or stopped by peer.
	EventStreamCreatable = "stream_creatable" // Maximum streams increased by peer.
	EventStreamComplete  = "stream_complete"  // All sending data has been acked.
	EventStreamClosed    = "stream_closed"    // Stream is fully closed and no longer available.

	EventDatagramOpen     = "datagram_open"     // Datagram is supported by peer.
	EventDatagramWritable = "datagram_writable" // Datagram buffer is writable.
	EventDatagramReadable = "datagram_readable" // Received datagram.
)

// Event is a union structure of all events.
type Event struct {
	Type string // Type of event
	Data uint64 // Data associated with the event. For stream events, this is Stream ID.
}

func (s Event) String() string {
	return fmt.Sprintf("%s:%d", s.Type, s.Data)
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
func newEventStreamOpen(id uint64) Event {
	return Event{
		Type: EventStreamOpen,
		Data: id,
	}
}

// newEventStreamReadable creates an event where a STREAM frame was received and data is readable.
func newEventStreamReadable(id uint64) Event {
	return Event{
		Type: EventStreamReadable,
		Data: id,
	}
}

// newEventStreamWritable creates an event where the stream is available to add more data.
func newEventStreamWritable(id uint64) Event {
	return Event{
		Type: EventStreamWritable,
		Data: id,
	}
}

// newEventStreamWritable creates an event where the stream is available to add more data.
func newEventStreamCreatable(bidi bool, uni bool) Event {
	var directional uint64
	if bidi && uni {
		directional = 3
	} else if uni {
		directional = 2
	} else if bidi {
		directional = 1
	}
	return Event{
		Type: EventStreamCreatable,
		Data: directional,
	}
}

// newEventStreamComplete creates an event where all data of the stream has been acked by peer.
func newEventStreamComplete(id uint64) Event {
	return Event{
		Type: EventStreamComplete,
		Data: id,
	}
}

// newEventStreamClosed creates an event where the stream is fully closed and garbage collected.
func newEventStreamClosed(id uint64) Event {
	return Event{
		Type: EventStreamClosed,
		Data: id,
	}
}

// newEventDatagramOpen creates an event when peer accepts DATAGRAM.
func newEventDatagramOpen(max uint64) Event {
	return Event{
		Type: EventDatagramOpen,
		Data: max,
	}
}

// newEventDatagramWritable creates an event where DATAGRAM is available for sending.
func newEventDatagramWritable() Event {
	return Event{
		Type: EventDatagramWritable,
	}
}

// newEventDatagramReadable creates an event where a DATAGRAM frame was received.
func newEventDatagramReadable() Event {
	return Event{
		Type: EventDatagramReadable,
	}
}
